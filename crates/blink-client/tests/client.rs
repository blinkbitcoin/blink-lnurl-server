use blink_client::{
    BlinkClientError, Client, ClientConfig, CreateInvoiceRequest, CreatedInvoice,
    PRODUCTION_GRAPHQL_ENDPOINT,
};
use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn invoice_request(wallet_id: &'static str) -> CreateInvoiceRequest<'static> {
    CreateInvoiceRequest {
        wallet_id,
        amount_sat: 21_000,
        description_hash_hex: Some("f".repeat(64)),
        expires_in_minutes: Some(30),
    }
}

fn assert_graphql_invoice_request(
    request: &Request,
    operation_name: &str,
    wallet_id: &str,
) -> bool {
    let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
        return false;
    };

    body.get("query")
        .and_then(Value::as_str)
        .is_some_and(|query| query.contains(operation_name))
        && body
            .pointer("/variables/input/recipientWalletId")
            .and_then(Value::as_str)
            == Some(wallet_id)
        && body
            .pointer("/variables/input/amount")
            .and_then(Value::as_u64)
            == Some(21_000)
        && body
            .pointer("/variables/input/descriptionHash")
            .and_then(Value::as_str)
            .is_some_and(|hash| hash.len() == 64)
        && body
            .pointer("/variables/input/expiresIn")
            .and_then(Value::as_u64)
            == Some(30)
}

async fn mount_invoice_response(
    server: &MockServer,
    operation_name: &'static str,
    wallet_id: &'static str,
) {
    let operation_field = operation_name;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(move |request: &Request| {
            assert_graphql_invoice_request(request, operation_name, wallet_id)
        })
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                operation_field: {
                    "invoice": {
                        "paymentRequest": "lnbc1mocked",
                        "paymentHash": "hash123"
                    },
                    "errors": []
                }
            }
        })))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn creates_btc_invoice_with_selected_wallet() {
    let server = MockServer::start().await;
    mount_invoice_response(
        &server,
        "lnInvoiceCreateOnBehalfOfRecipient",
        "btc-wallet-id",
    )
    .await;

    let client = Client::new(ClientConfig::new(format!("{}/graphql", server.uri())));
    let invoice = client
        .create_btc_invoice(invoice_request("btc-wallet-id"))
        .await
        .expect("BTC invoice should be created through mocked Blink GraphQL");

    assert_eq!(
        invoice,
        CreatedInvoice {
            bolt11: "lnbc1mocked".to_string(),
            payment_hash: "hash123".to_string(),
        }
    );
}

#[tokio::test]
async fn creates_usd_invoice_with_selected_wallet() {
    let server = MockServer::start().await;
    mount_invoice_response(
        &server,
        "lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient",
        "usd-wallet-id",
    )
    .await;

    let client = Client::new(ClientConfig::new(format!("{}/graphql", server.uri())));
    let invoice = client
        .create_usd_invoice(invoice_request("usd-wallet-id"))
        .await
        .expect("USD invoice should be created through mocked Blink GraphQL");

    assert_eq!(invoice.payment_hash, "hash123");
    assert_eq!(invoice.bolt11, "lnbc1mocked");
}

#[tokio::test]
async fn uses_configured_endpoint_override() {
    let server = MockServer::start().await;
    mount_invoice_response(
        &server,
        "lnInvoiceCreateOnBehalfOfRecipient",
        "btc-wallet-id",
    )
    .await;

    let config = ClientConfig::new(format!("{}/graphql", server.uri()));
    assert_ne!(config.endpoint(), PRODUCTION_GRAPHQL_ENDPOINT);

    let client = Client::new(config);
    let invoice = client
        .create_btc_invoice(invoice_request("btc-wallet-id"))
        .await
        .expect("endpoint override should route request to wiremock server");

    assert_eq!(invoice.bolt11, "lnbc1mocked");
}

#[tokio::test]
async fn maps_top_level_graphql_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "errors": [{ "message": "query failed" }]
        })))
        .mount(&server)
        .await;

    let client = Client::new(ClientConfig::new(format!("{}/graphql", server.uri())));
    let error = client
        .create_btc_invoice(invoice_request("btc-wallet-id"))
        .await
        .expect_err("top-level GraphQL errors must not be accepted as invoices");

    let BlinkClientError::Graphql(errors) = error else {
        panic!("expected Graphql error");
    };
    assert_eq!(errors[0].message, "query failed");
}

#[tokio::test]
async fn maps_payload_errors_to_api_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "lnInvoiceCreateOnBehalfOfRecipient": {
                    "invoice": null,
                    "errors": [{ "message": "wallet not found" }]
                }
            }
        })))
        .mount(&server)
        .await;

    let client = Client::new(ClientConfig::new(format!("{}/graphql", server.uri())));
    let error = client
        .create_btc_invoice(invoice_request("btc-wallet-id"))
        .await
        .expect_err("payload errors must be semantic Blink API failures");

    let BlinkClientError::ApiFailure(message) = error else {
        panic!("expected ApiFailure error");
    };
    assert_eq!(message, "wallet not found");
}

#[tokio::test]
async fn maps_missing_invoice_fields_to_malformed_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "lnInvoiceCreateOnBehalfOfRecipient": {
                    "invoice": { "paymentRequest": "lnbc1mocked" },
                    "errors": []
                }
            }
        })))
        .mount(&server)
        .await;

    let client = Client::new(ClientConfig::new(format!("{}/graphql", server.uri())));
    let error = client
        .create_btc_invoice(invoice_request("btc-wallet-id"))
        .await
        .expect_err("missing payment hash must be rejected");

    assert!(matches!(error, BlinkClientError::MalformedResponse(_)));
}
