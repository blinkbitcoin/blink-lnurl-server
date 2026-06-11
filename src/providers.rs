use std::str::FromStr;
use std::sync::Arc;

use crate::repository::{AccountProvider, ResolvedRecipient, WalletKind};
use bitcoin::secp256k1::PublicKey;
use blink_client::BlinkClientError;

const SPARK_PAYMENT_STATUS_PHASE_7_DEFERRAL: &str = "DEF-03-SPARK-PAYMENT-STATUS-PHASE-7: Spark payment status remains route-owned until Phase 7 SETL-01 settlement dispatch";

#[derive(Debug, Clone)]
pub struct CreateInvoiceRequest<'a> {
    pub recipient: &'a ResolvedRecipient,
    pub wallet: Option<WalletKind>,
    pub amount_sat: u64,
    pub description_hash: [u8; 32],
    pub expiry: Option<u32>,
    pub include_spark_address: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderInvoice {
    pub bolt11: String,
    pub wallet_kind: WalletKind,
    pub wallet_id: Option<String>,
    pub provider_payment_hash: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PaymentStatusRequest<'a> {
    pub payment_hash: &'a str,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPaymentStatus {
    pub settled: bool,
    pub preimage: Option<String>,
    pub amount_received_sat: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("unsupported provider: {0:?}")]
    UnsupportedProvider(AccountProvider),
    #[error("unsupported wallet {wallet:?} for provider {provider:?}")]
    UnsupportedWallet {
        provider: AccountProvider,
        wallet: WalletKind,
    },
    #[error("missing Spark pubkey")]
    MissingSparkPubkey,
    #[error("invalid Spark pubkey")]
    InvalidSparkPubkey,
    #[error("missing Blink default wallet")]
    MissingBlinkDefaultWallet,
    #[error("missing Blink BTC wallet id")]
    MissingBlinkBtcWalletId,
    #[error("missing Blink USD wallet id")]
    MissingBlinkUsdWalletId,
    #[error("Blink invoice creation failed: {0}")]
    BlinkInvoiceCreationFailed(#[source] BlinkClientError),
    #[error("Blink payment status unavailable: {0}")]
    BlinkPaymentStatusUnavailable(#[source] BlinkClientError),
    #[error("invoice creation failed: {0}")]
    InvoiceCreationFailed(anyhow::Error),
    #[error("payment status unavailable: {0}")]
    PaymentStatusUnavailable(anyhow::Error),
}

pub struct BlinkProvider {
    client: blink_client::Client,
}

impl BlinkProvider {
    pub fn new(client: blink_client::Client) -> Self {
        Self { client }
    }
}

fn select_blink_wallet_id(
    recipient: &ResolvedRecipient,
    requested_wallet: Option<WalletKind>,
) -> Result<(WalletKind, &str), ProviderError> {
    let wallet = requested_wallet
        .or(recipient.default_wallet)
        .ok_or(ProviderError::MissingBlinkDefaultWallet)?;

    let wallet_id = match wallet {
        WalletKind::Btc => recipient
            .btc_wallet_id
            .as_deref()
            .ok_or(ProviderError::MissingBlinkBtcWalletId)?,
        WalletKind::Usd => recipient
            .usd_wallet_id
            .as_deref()
            .ok_or(ProviderError::MissingBlinkUsdWalletId)?,
    };

    Ok((wallet, wallet_id))
}

#[async_trait::async_trait]
pub trait LnurlProvider: Send + Sync {
    async fn create_invoice(
        &self,
        request: CreateInvoiceRequest<'_>,
    ) -> Result<ProviderInvoice, ProviderError>;

    #[allow(dead_code)]
    async fn payment_status(
        &self,
        request: PaymentStatusRequest<'_>,
    ) -> Result<ProviderPaymentStatus, ProviderError>;
}

pub struct SparkProvider {
    wallet: Option<Arc<spark_wallet::SparkWallet>>,
}

impl SparkProvider {
    pub fn new(wallet: Arc<spark_wallet::SparkWallet>) -> Self {
        Self {
            wallet: Some(wallet),
        }
    }

    #[cfg(test)]
    fn new_without_wallet_for_tests() -> Self {
        Self { wallet: None }
    }
}

#[async_trait::async_trait]
impl LnurlProvider for SparkProvider {
    async fn create_invoice(
        &self,
        request: CreateInvoiceRequest<'_>,
    ) -> Result<ProviderInvoice, ProviderError> {
        if request.recipient.provider != AccountProvider::Spark {
            return Err(ProviderError::UnsupportedProvider(
                request.recipient.provider,
            ));
        }

        match request.wallet {
            None | Some(WalletKind::Btc) => {}
            Some(WalletKind::Usd) => {
                return Err(ProviderError::UnsupportedWallet {
                    provider: AccountProvider::Spark,
                    wallet: WalletKind::Usd,
                });
            }
        }

        let Some(spark_pubkey) = request.recipient.spark_pubkey.as_deref() else {
            return Err(ProviderError::MissingSparkPubkey);
        };
        let pubkey =
            PublicKey::from_str(spark_pubkey).map_err(|_| ProviderError::InvalidSparkPubkey)?;
        let Some(wallet) = self.wallet.as_ref() else {
            return Err(ProviderError::PaymentStatusUnavailable(anyhow::anyhow!(
                "Spark wallet unavailable in provider unit test"
            )));
        };

        let invoice = wallet
            .create_lightning_invoice(
                request.amount_sat,
                Some(spark_wallet::InvoiceDescription::DescriptionHash(
                    request.description_hash,
                )),
                Some(pubkey),
                request.expiry,
                request.include_spark_address,
            )
            .await
            .map_err(|e| ProviderError::InvoiceCreationFailed(e.into()))?;

        Ok(ProviderInvoice {
            bolt11: invoice.invoice,
            wallet_kind: WalletKind::Btc,
            wallet_id: None,
            provider_payment_hash: None,
        })
    }

    async fn payment_status(
        &self,
        request: PaymentStatusRequest<'_>,
    ) -> Result<ProviderPaymentStatus, ProviderError> {
        let _ = request;
        Err(ProviderError::PaymentStatusUnavailable(anyhow::anyhow!(
            SPARK_PAYMENT_STATUS_PHASE_7_DEFERRAL
        )))
    }
}

#[async_trait::async_trait]
impl LnurlProvider for BlinkProvider {
    async fn create_invoice(
        &self,
        request: CreateInvoiceRequest<'_>,
    ) -> Result<ProviderInvoice, ProviderError> {
        if request.recipient.provider != AccountProvider::Blink {
            return Err(ProviderError::UnsupportedProvider(
                request.recipient.provider,
            ));
        }

        let (wallet, wallet_id) = select_blink_wallet_id(request.recipient, request.wallet)?;
        let client_request = blink_client::CreateInvoiceRequest {
            wallet_id,
            amount_sat: request.amount_sat,
            description_hash_hex: Some(hex::encode(request.description_hash)),
            expires_in_minutes: request.expiry,
        };

        let invoice = match wallet {
            WalletKind::Btc => self.client.create_btc_invoice(client_request).await,
            WalletKind::Usd => self.client.create_usd_invoice(client_request).await,
        }
        .map_err(ProviderError::BlinkInvoiceCreationFailed)?;

        Ok(ProviderInvoice {
            bolt11: invoice.bolt11,
            wallet_kind: wallet,
            wallet_id: Some(wallet_id.to_string()),
            provider_payment_hash: Some(invoice.payment_hash),
        })
    }

    async fn payment_status(
        &self,
        request: PaymentStatusRequest<'_>,
    ) -> Result<ProviderPaymentStatus, ProviderError> {
        let status = self
            .client
            .payment_status(request.payment_hash)
            .await
            .map_err(ProviderError::BlinkPaymentStatusUnavailable)?;

        Ok(ProviderPaymentStatus {
            settled: status.settled,
            preimage: status.preimage,
            amount_received_sat: status.amount_received_sat,
        })
    }
}

pub struct ProviderRegistry {
    spark: Arc<SparkProvider>,
    blink: Arc<BlinkProvider>,
}

impl ProviderRegistry {
    pub fn new(wallet: Arc<spark_wallet::SparkWallet>, blink_client: blink_client::Client) -> Self {
        Self {
            spark: Arc::new(SparkProvider::new(wallet)),
            blink: Arc::new(BlinkProvider::new(blink_client)),
        }
    }

    pub fn provider_for(&self, provider: AccountProvider) -> &dyn LnurlProvider {
        match provider {
            AccountProvider::Spark => self.spark.as_ref(),
            AccountProvider::Blink => self.blink.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::repository::AccountIdentifierKind;

    use super::*;

    fn spark_provider_for_unit_tests() -> SparkProvider {
        // These tests exercise provider-owned capability checks that must run before
        // the Spark SDK wallet is dereferenced.
        SparkProvider::new_without_wallet_for_tests()
    }

    fn recipient(provider: AccountProvider, wallet: Option<WalletKind>) -> ResolvedRecipient {
        ResolvedRecipient {
            account_id: format!("acct_{}", provider.as_str()),
            provider,
            domain: "localhost:8080".to_string(),
            identifier: "alice".to_string(),
            identifier_kind: AccountIdentifierKind::Username,
            description: "Alice".to_string(),
            spark_pubkey: Some("02".repeat(33)),
            blink_account_id: None,
            btc_wallet_id: None,
            usd_wallet_id: None,
            default_wallet: wallet,
        }
    }

    #[test]
    fn registry_routes_spark_and_blink() {
        let registry = ProviderRegistry {
            spark: Arc::new(SparkProvider::new_without_wallet_for_tests()),
            blink: Arc::new(BlinkProvider::new(blink_client::Client::new(
                blink_client::ClientConfig::new("http://127.0.0.1/graphql"),
            ))),
        };

        assert!(std::ptr::addr_eq(
            registry.provider_for(AccountProvider::Spark),
            registry.spark.as_ref() as &dyn LnurlProvider,
        ));
        assert!(std::ptr::addr_eq(
            registry.provider_for(AccountProvider::Blink),
            registry.blink.as_ref() as &dyn LnurlProvider,
        ));
    }

    #[tokio::test]
    async fn spark_provider_rejects_usd_wallet() {
        let provider = spark_provider_for_unit_tests();
        let recipient = recipient(AccountProvider::Spark, None);

        let err = provider
            .create_invoice(CreateInvoiceRequest {
                recipient: &recipient,
                wallet: Some(WalletKind::Usd),
                amount_sat: 1,
                description_hash: [0; 32],
                expiry: None,
                include_spark_address: false,
            })
            .await
            .expect_err("Spark must reject USD wallet intent");

        assert!(matches!(
            err,
            ProviderError::UnsupportedWallet {
                provider: AccountProvider::Spark,
                wallet: WalletKind::Usd,
            }
        ));
    }

    #[tokio::test]
    async fn spark_provider_accepts_default_and_btc_wallet_intents() {
        let provider = spark_provider_for_unit_tests();
        let recipient = recipient(AccountProvider::Spark, None);

        for wallet in [None, Some(WalletKind::Btc)] {
            let result = provider
                .create_invoice(CreateInvoiceRequest {
                    recipient: &recipient,
                    wallet,
                    amount_sat: 1,
                    description_hash: [0; 32],
                    expiry: None,
                    include_spark_address: false,
                })
                .await;

            assert!(
                !matches!(result, Err(ProviderError::UnsupportedWallet { .. })),
                "default/BTC wallet intent must pass Spark capability gate"
            );
        }
    }

    #[tokio::test]
    async fn spark_payment_status_error_carries_phase_7_deferral_marker() {
        let provider = spark_provider_for_unit_tests();

        let err = provider
            .payment_status(PaymentStatusRequest {
                payment_hash: "payment_hash",
            })
            .await
            .expect_err("Spark payment status remains deferred to Phase 7");

        let message = err.to_string();
        assert!(message.contains("DEF-03-SPARK-PAYMENT-STATUS-PHASE-7"));
        assert!(message.contains("Phase 7 SETL-01"));
    }

    fn blink_recipient(default_wallet: Option<WalletKind>) -> ResolvedRecipient {
        ResolvedRecipient {
            account_id: "acct_blink".to_string(),
            provider: AccountProvider::Blink,
            domain: "localhost:8080".to_string(),
            identifier: "alice".to_string(),
            identifier_kind: AccountIdentifierKind::Username,
            description: "Alice".to_string(),
            spark_pubkey: None,
            blink_account_id: Some("blink_account".to_string()),
            btc_wallet_id: Some("btc_wallet".to_string()),
            usd_wallet_id: Some("usd_wallet".to_string()),
            default_wallet,
        }
    }

    async fn start_blink_mock_server(
        request_body_tx: tokio::sync::mpsc::Sender<serde_json::Value>,
    ) -> String {
        let app = axum::Router::new().route(
            "/graphql",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let request_body_tx = request_body_tx.clone();
                async move {
                    request_body_tx
                        .send(body)
                        .await
                        .expect("request body receiver should stay open");
                    axum::Json(serde_json::json!({
                        "data": {
                            "lnInvoiceCreateOnBehalfOfRecipient": {
                                "invoice": {
                                    "paymentRequest": "lnbc_btc_invoice",
                                    "paymentHash": "btc_payment_hash"
                                },
                                "errors": []
                            },
                            "lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient": {
                                "invoice": {
                                    "paymentRequest": "lnbc_usd_invoice",
                                    "paymentHash": "usd_payment_hash"
                                },
                                "errors": []
                            }
                        }
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener should bind");
        let addr = listener.local_addr().expect("mock listener has addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock server should serve");
        });
        format!("http://{addr}/graphql")
    }

    async fn start_blink_status_mock_server() -> String {
        let app = axum::Router::new().route(
            "/graphql",
            axum::routing::post(
                |axum::Json(_body): axum::Json<serde_json::Value>| async move {
                    axum::Json(serde_json::json!({
                        "data": {
                            "lnInvoicePaymentStatusByHash": {
                                "status": "PAID",
                                "paymentHash": "payment_hash",
                                "paymentRequest": "lnbc_invoice"
                            }
                        }
                    }))
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener should bind");
        let addr = listener.local_addr().expect("mock listener has addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock server should serve");
        });
        format!("http://{addr}/graphql")
    }

    fn blink_invoice_request_with_expiry(
        recipient: &ResolvedRecipient,
        wallet: Option<WalletKind>,
        expiry: Option<u32>,
    ) -> CreateInvoiceRequest<'_> {
        CreateInvoiceRequest {
            recipient,
            wallet,
            amount_sat: 21,
            description_hash: [7; 32],
            expiry,
            include_spark_address: true,
        }
    }

    fn blink_invoice_request(
        recipient: &ResolvedRecipient,
        wallet: Option<WalletKind>,
    ) -> CreateInvoiceRequest<'_> {
        blink_invoice_request_with_expiry(recipient, wallet, None)
    }

    #[test]
    fn blink_registry_dispatches_to_blink_provider() {
        let registry = ProviderRegistry {
            spark: Arc::new(SparkProvider::new_without_wallet_for_tests()),
            blink: Arc::new(BlinkProvider::new(blink_client::Client::new(
                blink_client::ClientConfig::new("http://127.0.0.1/graphql"),
            ))),
        };

        assert!(std::ptr::addr_eq(
            registry.provider_for(AccountProvider::Spark),
            registry.spark.as_ref() as &dyn LnurlProvider,
        ));
        assert!(std::ptr::addr_eq(
            registry.provider_for(AccountProvider::Blink),
            registry.blink.as_ref() as &dyn LnurlProvider,
        ));
    }

    #[tokio::test]
    async fn blink_provider_rejects_missing_wallet_selection_and_selected_ids() {
        let provider = BlinkProvider::new(blink_client::Client::new(
            blink_client::ClientConfig::new("http://127.0.0.1/graphql"),
        ));
        let no_default = blink_recipient(None);
        let err = provider
            .create_invoice(blink_invoice_request(&no_default, None))
            .await
            .expect_err("Blink requires explicit or default wallet selection");
        assert!(matches!(err, ProviderError::MissingBlinkDefaultWallet));

        let mut missing_btc = blink_recipient(Some(WalletKind::Btc));
        missing_btc.btc_wallet_id = None;
        let err = provider
            .create_invoice(blink_invoice_request(&missing_btc, Some(WalletKind::Btc)))
            .await
            .expect_err("selected BTC wallet id must be present");
        assert!(matches!(err, ProviderError::MissingBlinkBtcWalletId));

        let mut missing_usd = blink_recipient(Some(WalletKind::Usd));
        missing_usd.usd_wallet_id = None;
        let err = provider
            .create_invoice(blink_invoice_request(&missing_usd, Some(WalletKind::Usd)))
            .await
            .expect_err("selected USD wallet id must be present");
        assert!(matches!(err, ProviderError::MissingBlinkUsdWalletId));
    }

    #[tokio::test]
    async fn blink_provider_selects_explicit_and_default_wallets_for_btc_and_usd_invoices() {
        let (request_body_tx, mut request_body_rx) = tokio::sync::mpsc::channel(2);
        let endpoint = start_blink_mock_server(request_body_tx).await;
        let provider = BlinkProvider::new(blink_client::Client::new(
            blink_client::ClientConfig::new(endpoint),
        ));
        let recipient = blink_recipient(Some(WalletKind::Usd));

        let btc_invoice = provider
            .create_invoice(blink_invoice_request(&recipient, Some(WalletKind::Btc)))
            .await
            .expect("BTC invoice should be created");
        assert_eq!(btc_invoice.bolt11, "lnbc_btc_invoice");

        let btc_body = request_body_rx
            .recv()
            .await
            .expect("BTC request body should be captured");
        assert!(
            btc_body["query"]
                .as_str()
                .unwrap()
                .contains("lnInvoiceCreateOnBehalfOfRecipient")
        );
        assert_eq!(
            btc_body["variables"]["input"]["recipientWalletId"],
            "btc_wallet"
        );
        assert_eq!(
            btc_body["variables"]["input"]["descriptionHash"],
            hex::encode([7; 32])
        );
        assert!(btc_body["variables"]["input"].get("expiresIn").is_none());

        let usd_invoice = provider
            .create_invoice(blink_invoice_request(&recipient, None))
            .await
            .expect("default USD invoice should be created");
        assert_eq!(usd_invoice.bolt11, "lnbc_usd_invoice");

        let usd_body = request_body_rx
            .recv()
            .await
            .expect("USD request body should be captured");
        assert!(
            usd_body["query"]
                .as_str()
                .unwrap()
                .contains("lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient")
        );
        assert_eq!(
            usd_body["variables"]["input"]["recipientWalletId"],
            "usd_wallet"
        );
        assert_eq!(
            usd_body["variables"]["input"]["descriptionHash"],
            hex::encode([7; 32])
        );
        assert!(usd_body["variables"]["input"].get("expiresIn").is_none());
    }

    #[tokio::test]
    async fn provider_invoice_metadata_covers_blink_wallet_selection_and_spark_capability_rules() {
        // COMP-04, LNURL-04, LNURL-05, D-12, and D-13: provider invoices expose
        // selected wallet metadata while Spark remains BTC/default only.
        let (request_body_tx, mut request_body_rx) = tokio::sync::mpsc::channel(3);
        let endpoint = start_blink_mock_server(request_body_tx).await;
        let blink_provider = BlinkProvider::new(blink_client::Client::new(
            blink_client::ClientConfig::new(endpoint),
        ));
        let default_btc_recipient = blink_recipient(Some(WalletKind::Btc));

        let default_invoice = blink_provider
            .create_invoice(blink_invoice_request_with_expiry(
                &default_btc_recipient,
                None,
                None,
            ))
            .await
            .expect("default BTC invoice should be created");
        assert_eq!(default_invoice.wallet_kind, WalletKind::Btc);
        assert_eq!(default_invoice.wallet_id.as_deref(), Some("btc_wallet"));
        assert_eq!(
            default_invoice.provider_payment_hash.as_deref(),
            Some("btc_payment_hash")
        );
        let _default_body = request_body_rx
            .recv()
            .await
            .expect("default BTC request body should be captured");

        let explicit_btc_invoice = blink_provider
            .create_invoice(blink_invoice_request_with_expiry(
                &default_btc_recipient,
                Some(WalletKind::Btc),
                None,
            ))
            .await
            .expect("explicit BTC invoice should be created");
        assert_eq!(explicit_btc_invoice.wallet_kind, WalletKind::Btc);
        assert_eq!(
            explicit_btc_invoice.wallet_id.as_deref(),
            Some("btc_wallet")
        );
        let explicit_btc_body = request_body_rx
            .recv()
            .await
            .expect("explicit BTC request body should be captured");
        assert_eq!(
            explicit_btc_body["variables"]["input"]["recipientWalletId"],
            "btc_wallet"
        );

        let explicit_usd_invoice = blink_provider
            .create_invoice(blink_invoice_request_with_expiry(
                &default_btc_recipient,
                Some(WalletKind::Usd),
                None,
            ))
            .await
            .expect("explicit USD invoice should be created");
        assert_eq!(explicit_usd_invoice.wallet_kind, WalletKind::Usd);
        assert_eq!(
            explicit_usd_invoice.wallet_id.as_deref(),
            Some("usd_wallet")
        );
        assert_eq!(
            explicit_usd_invoice.provider_payment_hash.as_deref(),
            Some("usd_payment_hash")
        );
        let explicit_usd_body = request_body_rx
            .recv()
            .await
            .expect("explicit USD request body should be captured");
        assert_eq!(
            explicit_usd_body["variables"]["input"]["recipientWalletId"],
            "usd_wallet"
        );

        let spark_provider = spark_provider_for_unit_tests();
        let spark_recipient = recipient(AccountProvider::Spark, None);
        let err = spark_provider
            .create_invoice(CreateInvoiceRequest {
                recipient: &spark_recipient,
                wallet: Some(WalletKind::Usd),
                amount_sat: 1,
                description_hash: [0; 32],
                expiry: Some(1),
                include_spark_address: false,
            })
            .await
            .expect_err("Spark must reject USD wallet intent before wallet use");
        assert!(matches!(
            err,
            ProviderError::UnsupportedWallet {
                provider: AccountProvider::Spark,
                wallet: WalletKind::Usd,
            }
        ));

        for wallet in [None, Some(WalletKind::Btc)] {
            let result = spark_provider
                .create_invoice(CreateInvoiceRequest {
                    recipient: &spark_recipient,
                    wallet,
                    amount_sat: 1,
                    description_hash: [0; 32],
                    expiry: Some(2),
                    include_spark_address: false,
                })
                .await;
            assert!(
                !matches!(result, Err(ProviderError::UnsupportedWallet { .. })),
                "Spark default/BTC intent should pass COMP-04 capability gate"
            );
        }
    }

    #[tokio::test]
    async fn blink_expiry_forwards_route_validated_minutes_without_provider_policy() {
        // LNURL-04/D-05/D-06/D-07/D-08/D-09/D-10: route-owned callback code
        // converts public seconds and enforces limits; provider forwards already
        // accepted minute values unchanged and omits expiry when absent.
        let (request_body_tx, mut request_body_rx) = tokio::sync::mpsc::channel(3);
        let endpoint = start_blink_mock_server(request_body_tx).await;
        let provider = BlinkProvider::new(blink_client::Client::new(
            blink_client::ClientConfig::new(endpoint),
        ));
        let recipient = blink_recipient(Some(WalletKind::Btc));

        for expiry in [None, Some(1), Some(2)] {
            provider
                .create_invoice(blink_invoice_request_with_expiry(
                    &recipient,
                    Some(WalletKind::Btc),
                    expiry,
                ))
                .await
                .expect("Blink invoice should be created for provider-ready expiry");
            let body = request_body_rx
                .recv()
                .await
                .expect("Blink request body should be captured");

            match expiry {
                Some(minutes) => {
                    assert_eq!(body["variables"]["input"]["expiresIn"], minutes);
                }
                None => {
                    assert!(body["variables"]["input"].get("expiresIn").is_none());
                }
            }
        }
    }

    #[tokio::test]
    async fn blink_provider_maps_payment_status_without_fabricating_optional_fields() {
        let endpoint = start_blink_status_mock_server().await;
        let provider = BlinkProvider::new(blink_client::Client::new(
            blink_client::ClientConfig::new(endpoint),
        ));

        let status = provider
            .payment_status(PaymentStatusRequest {
                payment_hash: "payment_hash",
            })
            .await
            .expect("Blink payment status should map through provider");

        assert!(status.settled);
        assert_eq!(status.preimage, None);
        assert_eq!(status.amount_received_sat, None);
    }
}
