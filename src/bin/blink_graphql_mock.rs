use std::str::FromStr;

use axum::Router;
use axum::extract::Json;
use axum::http::StatusCode;
use axum::routing::{get, post};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use serde_json::{Value, json};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:0";
const FIXTURE_STATUS_PREIMAGE: [u8; 32] = [9_u8; 32];
const FIXTURE_HOOKS_PREIMAGE: [u8; 32] = [10_u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockScenario {
    BtcInvoice,
    UsdInvoice,
    StatusPaid,
    StatusPending,
    GraphqlError,
    Malformed,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    let addr = listener.local_addr()?;

    let app = Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/graphql", post(graphql_handler));

    println!("http://{addr}/graphql");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn graphql_handler(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    match scenario_from_request(&body) {
        MockScenario::BtcInvoice => (
            StatusCode::OK,
            Json(mock_invoice_response(&body, Wallet::Btc)),
        ),
        MockScenario::UsdInvoice => (
            StatusCode::OK,
            Json(mock_invoice_response(&body, Wallet::Usd)),
        ),
        MockScenario::StatusPaid => (StatusCode::OK, Json(mock_status_response(&body, true))),
        MockScenario::StatusPending => (StatusCode::OK, Json(mock_status_response(&body, false))),
        MockScenario::GraphqlError => (
            StatusCode::OK,
            Json(json!({
                "errors": [{ "message": "mock graphql error" }]
            })),
        ),
        MockScenario::Malformed => (StatusCode::OK, Json(json!({ "data": {} }))),
    }
}

fn scenario_from_request(body: &Value) -> MockScenario {
    let query = body
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let input = body.pointer("/variables/input").unwrap_or(&Value::Null);
    let wallet_id = input
        .get("recipientWalletId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let payment_hash = input
        .get("paymentHash")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if wallet_id.contains("malformed") || payment_hash == "malformed" {
        return MockScenario::Malformed;
    }
    if wallet_id.contains("error") || payment_hash == "graphql_error" {
        return MockScenario::GraphqlError;
    }
    if query.contains("lnInvoicePaymentStatusByHash") {
        if fixture_status_preimage_for_hash(payment_hash).is_some() || payment_hash.contains("paid")
        {
            return MockScenario::StatusPaid;
        }
        return MockScenario::StatusPending;
    }
    if query.contains("lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient") {
        return MockScenario::UsdInvoice;
    }
    MockScenario::BtcInvoice
}

#[derive(Debug, Clone, Copy)]
enum Wallet {
    Btc,
    Usd,
}

fn mock_invoice_response(body: &Value, wallet: Wallet) -> Value {
    let input = body.pointer("/variables/input").unwrap_or(&Value::Null);
    let wallet_id = input
        .get("recipientWalletId")
        .and_then(Value::as_str)
        .unwrap_or("wallet");
    let amount_sat = input.get("amount").and_then(Value::as_u64).unwrap_or(1);
    let description_hash = input
        .get("descriptionHash")
        .and_then(Value::as_str)
        .and_then(parse_description_hash)
        .unwrap_or_else(|| sha256::Hash::hash(wallet_id.as_bytes()));

    let preimage = if wallet_id.contains("paid-fallback-hooks") {
        FIXTURE_HOOKS_PREIMAGE
    } else if wallet_id.contains("paid-fallback") {
        FIXTURE_STATUS_PREIMAGE
    } else {
        deterministic_preimage(wallet_id, amount_sat, wallet)
    };
    let payment_hash = sha256::Hash::hash(&preimage).to_string();
    let invoice = build_invoice(preimage, description_hash, amount_sat);

    match wallet {
        Wallet::Btc => json!({
            "data": {
                "lnInvoiceCreateOnBehalfOfRecipient": {
                    "invoice": { "paymentRequest": invoice, "paymentHash": payment_hash },
                    "errors": []
                }
            }
        }),
        Wallet::Usd => json!({
            "data": {
                "lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient": {
                    "invoice": { "paymentRequest": invoice, "paymentHash": payment_hash },
                    "errors": []
                }
            }
        }),
    }
}

fn mock_status_response(body: &Value, paid: bool) -> Value {
    let requested_hash = body
        .pointer("/variables/input/paymentHash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let payment_hash = if requested_hash.is_empty() {
        fixture_status_payment_hash()
    } else {
        requested_hash.to_string()
    };
    let preimage = paid.then(|| {
        fixture_status_preimage_for_hash(&payment_hash)
            .map(hex::encode)
            .unwrap_or_else(|| hex::encode(FIXTURE_STATUS_PREIMAGE))
    });
    json!({
        "data": {
            "lnInvoicePaymentStatusByHash": {
                "status": if paid { "PAID" } else { "PENDING" },
                "paymentHash": payment_hash,
                "paymentRequest": null,
                "paymentPreimage": preimage
            }
        }
    })
}

fn fixture_status_payment_hash() -> String {
    sha256::Hash::hash(&FIXTURE_STATUS_PREIMAGE).to_string()
}

fn fixture_status_preimage_for_hash(payment_hash: &str) -> Option<[u8; 32]> {
    [FIXTURE_STATUS_PREIMAGE, FIXTURE_HOOKS_PREIMAGE]
        .into_iter()
        .find(|preimage| sha256::Hash::hash(preimage).to_string() == payment_hash)
}

fn parse_description_hash(value: &str) -> Option<sha256::Hash> {
    sha256::Hash::from_str(value).ok()
}

fn deterministic_preimage(wallet_id: &str, amount_sat: u64, wallet: Wallet) -> [u8; 32] {
    let tag = match wallet {
        Wallet::Btc => "btc",
        Wallet::Usd => "usd",
    };
    let seed = sha256::Hash::hash(format!("{tag}:{wallet_id}:{amount_sat}").as_bytes());
    seed.to_byte_array()
}

fn build_invoice(preimage: [u8; 32], description_hash: sha256::Hash, amount_sat: u64) -> String {
    let payment_hash = sha256::Hash::hash(&preimage);
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[42_u8; 32]).expect("static signing key is valid");
    InvoiceBuilder::new(Currency::Regtest)
        .description_hash(description_hash)
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([0_u8; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .amount_milli_satoshis(amount_sat.saturating_mul(1000))
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &key))
        .expect("fixture invoice should build")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};

    #[test]
    fn scenario_from_request_uses_wallet_and_payment_hash() {
        let body = serde_json::json!({
            "query": "mutation LnInvoiceCreateOnBehalfOfRecipient { lnInvoiceCreateOnBehalfOfRecipient { invoice { paymentHash } } }",
            "variables": { "input": { "recipientWalletId": "btc-wallet-error" } }
        });

        assert_eq!(scenario_from_request(&body), MockScenario::GraphqlError);
    }

    #[test]
    fn mock_invoice_response_contains_parseable_description_hash_invoice() {
        let description_hash = sha256::Hash::hash(b"metadata");
        let body = json!({
            "query": "mutation LnInvoiceCreateOnBehalfOfRecipient",
            "variables": {
                "input": {
                    "recipientWalletId": "btc-wallet",
                    "amount": 21,
                    "descriptionHash": description_hash.to_string()
                }
            }
        });

        let response = mock_invoice_response(&body, Wallet::Btc);
        let invoice = response
            .pointer("/data/lnInvoiceCreateOnBehalfOfRecipient/invoice/paymentRequest")
            .and_then(Value::as_str)
            .and_then(|value| Bolt11Invoice::from_str(value).ok())
            .expect("mock returns parseable invoice");

        assert_eq!(invoice.amount_milli_satoshis(), Some(21_000));
        assert!(matches!(
            invoice.description(),
            Bolt11InvoiceDescriptionRef::Hash(hash) if hash.0 == description_hash
        ));
    }
}
