use std::str::FromStr;
use std::sync::Arc;

use crate::repository::{AccountProvider, ResolvedRecipient, WalletKind};
use bitcoin::secp256k1::PublicKey;

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
    #[error("invoice creation failed: {0}")]
    InvoiceCreationFailed(anyhow::Error),
    #[error("payment status unavailable: {0}")]
    PaymentStatusUnavailable(anyhow::Error),
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
        })
    }

    async fn payment_status(
        &self,
        request: PaymentStatusRequest<'_>,
    ) -> Result<ProviderPaymentStatus, ProviderError> {
        let _ = request;
        Err(ProviderError::PaymentStatusUnavailable(anyhow::anyhow!(
            "Spark payment status remains route-owned until settlement dispatch migration"
        )))
    }
}

pub struct ProviderRegistry {
    spark: Arc<SparkProvider>,
}

impl ProviderRegistry {
    pub fn new(wallet: Arc<spark_wallet::SparkWallet>) -> Self {
        Self {
            spark: Arc::new(SparkProvider::new(wallet)),
        }
    }

    pub fn provider_for(
        &self,
        provider: AccountProvider,
    ) -> Result<&dyn LnurlProvider, ProviderError> {
        match provider {
            AccountProvider::Spark => Ok(self.spark.as_ref()),
            AccountProvider::Blink => {
                Err(ProviderError::UnsupportedProvider(AccountProvider::Blink))
            }
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
    fn registry_routes_spark_and_rejects_blink() {
        let registry = ProviderRegistry {
            spark: Arc::new(SparkProvider::new_without_wallet_for_tests()),
        };

        assert!(registry.provider_for(AccountProvider::Spark).is_ok());
        assert!(matches!(
            registry.provider_for(AccountProvider::Blink),
            Err(ProviderError::UnsupportedProvider(AccountProvider::Blink))
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
}
