use blink_client::{
    BlinkClientError, Client, ClientConfig, CreateInvoiceRequest, CreatedInvoice,
    PRODUCTION_GRAPHQL_ENDPOINT, PaymentStatus, PaymentStatusState,
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

// TEST-03 traceability: this file owns detailed Blink GraphQL request-body
// assertions. The mocked happy-path tests below cover BTC invoice creation, USD
// invoice creation, and payment status variants; the endpoint and malformed/error
// tests cover the deterministic no-live-Blink failure surfaces required by D-05
// through D-07.

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

fn assert_graphql_payment_status_request(request: &Request, payment_hash: &str) -> bool {
    let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
        return false;
    };

    body.get("query")
        .and_then(Value::as_str)
        .is_some_and(|query| {
            query.contains("LnInvoicePaymentStatusByHashQuery")
                && query.contains("lnInvoicePaymentStatusByHash")
                && query.contains("paymentPreimage")
        })
        && body
            .pointer("/variables/input/paymentHash")
            .and_then(Value::as_str)
            == Some(payment_hash)
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

#[tokio::test]
async fn payment_status_maps_paid_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(|request: &Request| assert_graphql_payment_status_request(request, "paid-hash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "lnInvoicePaymentStatusByHash": {
                    "status": "PAID",
                    "paymentHash": "paid-hash",
                    "paymentRequest": "lnbc1paid"
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(ClientConfig::new(format!("{}/graphql", server.uri())));
    let status = client
        .payment_status("paid-hash")
        .await
        .expect("paid payment status should parse");

    assert_eq!(
        status,
        PaymentStatus {
            state: PaymentStatusState::Paid,
            settled: true,
            payment_hash: "paid-hash".to_string(),
            payment_request: Some("lnbc1paid".to_string()),
            preimage: None,
            amount_received_sat: None,
        }
    );
}

#[tokio::test]
async fn payment_status_maps_paid_status_with_payment_preimage() {
    let server = MockServer::start().await;
    let preimage = "00".repeat(32);
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(|request: &Request| assert_graphql_payment_status_request(request, "paid-hash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "lnInvoicePaymentStatusByHash": {
                    "status": "PAID",
                    "paymentHash": "paid-hash",
                    "paymentRequest": "lnbc1paid",
                    "paymentPreimage": preimage
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(ClientConfig::new(format!("{}/graphql", server.uri())));
    let status = client
        .payment_status("paid-hash")
        .await
        .expect("paid payment status with preimage should parse");

    assert_eq!(
        status,
        PaymentStatus {
            state: PaymentStatusState::Paid,
            settled: true,
            payment_hash: "paid-hash".to_string(),
            payment_request: Some("lnbc1paid".to_string()),
            preimage: Some(preimage),
            amount_received_sat: None,
        }
    );
}

#[tokio::test]
async fn payment_status_maps_unsettled_status_without_payment_request() {
    for (blink_status, expected_state) in [
        ("PENDING", PaymentStatusState::Pending),
        ("EXPIRED", PaymentStatusState::Expired),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(|request: &Request| {
                assert_graphql_payment_status_request(request, "unsettled-hash")
            })
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "lnInvoicePaymentStatusByHash": {
                        "status": blink_status,
                        "paymentHash": "unsettled-hash"
                    }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(ClientConfig::new(format!("{}/graphql", server.uri())));
        let status = client
            .payment_status("unsettled-hash")
            .await
            .expect("unsettled payment status should parse");

        assert_eq!(status.state, expected_state);
        assert!(!status.settled);
        assert_eq!(status.payment_hash, "unsettled-hash");
        assert_eq!(status.payment_request, None);
        // D-06/D-11: current checked-in operation does not select preimage or amount.
        assert_eq!(status.preimage, None);
        assert_eq!(status.amount_received_sat, None);
    }
}

#[tokio::test]
async fn payment_status_maps_top_level_graphql_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(|request: &Request| assert_graphql_payment_status_request(request, "error-hash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "errors": [{ "message": "status query failed" }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(ClientConfig::new(format!("{}/graphql", server.uri())));
    let error = client
        .payment_status("error-hash")
        .await
        .expect_err("top-level GraphQL errors must not be accepted as status");

    let BlinkClientError::Graphql(errors) = error else {
        panic!("expected Graphql error");
    };
    assert_eq!(errors[0].message, "status query failed");
}

#[tokio::test]
async fn payment_status_rejects_malformed_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(|request: &Request| assert_graphql_payment_status_request(request, "bad-hash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "lnInvoicePaymentStatusByHash": {
                    "status": "PAID",
                    "paymentRequest": "lnbc1missinghash"
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(ClientConfig::new(format!("{}/graphql", server.uri())));
    let error = client
        .payment_status("bad-hash")
        .await
        .expect_err("missing payment hash must be rejected");

    assert!(matches!(error, BlinkClientError::MalformedResponse(_)));
}
