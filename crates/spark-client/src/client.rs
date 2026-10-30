use std::sync::Arc;

use spark::operator::rpc::{ConnectionManager, DefaultConnectionManager};
use spark::session_store::InMemorySessionStore;
use spark::signer::Signer;
use spark::ssp::ServiceProvider;
use spark::token::InMemoryTokenOutputStore;
use spark::tree::InMemoryTreeStore;
use spark_wallet::{DefaultSigner, InvoiceDescription, SparkWallet, SparkWalletConfig};

use crate::error::SparkClientError;
use crate::types::{
    ClientConfig, CreateInvoiceRequest, CreatedInvoice, SignedAuthPayload, SignedV2AuthPayload,
    VerifyMessageRequest, WebhookRegistrationRequest,
};
use lnurl_models::signed_message;

#[derive(Clone)]
pub struct Client {
    wallet: Arc<SparkWallet>,
    service_provider: Arc<ServiceProvider>,
}

impl Client {
    pub async fn new(config: ClientConfig) -> Result<Self, SparkClientError> {
        let mut spark_config = SparkWalletConfig::default_config(config.network);
        spark_config.service_provider_config.schema_endpoint = Some("graphql/spark/rc".to_string());

        let signer = Arc::new(
            DefaultSigner::new(&config.auth_seed, config.network)
                .map_err(|e| SparkClientError::WalletConstruction(e.into()))?,
        );
        let session_store = Arc::new(InMemorySessionStore::default());
        let connection_manager: Arc<dyn ConnectionManager> =
            Arc::new(DefaultConnectionManager::new());
        let service_provider = Arc::new(ServiceProvider::new(
            spark_config.service_provider_config.clone(),
            signer.clone(),
            session_store.clone(),
            None,
        ));

        let wallet = Arc::new(
            SparkWallet::new(
                spark_config,
                signer,
                session_store,
                Arc::new(InMemoryTreeStore::default()),
                Arc::new(InMemoryTokenOutputStore::default()),
                connection_manager,
                None,
                None,
                None,
                None,
                true,
                None,
            )
            .await
            .map_err(|e| SparkClientError::WalletConstruction(e.into()))?,
        );

        Ok(Self {
            wallet,
            service_provider,
        })
    }

    pub async fn create_lightning_invoice(
        &self,
        request: CreateInvoiceRequest,
    ) -> Result<CreatedInvoice, SparkClientError> {
        let invoice = self
            .wallet
            .create_lightning_invoice(
                request.amount_sat,
                Some(InvoiceDescription::DescriptionHash(
                    request.description_hash,
                )),
                Some(request.receiver_pubkey),
                request.expiry_secs,
                request.include_spark_address,
            )
            .await
            .map_err(|e| SparkClientError::InvoiceCreation(e.into()))?;

        Ok(CreatedInvoice {
            bolt11: invoice.invoice,
        })
    }

    pub async fn verify_message(
        &self,
        request: VerifyMessageRequest<'_>,
    ) -> Result<(), SparkClientError> {
        self.wallet
            .verify_message(request.message, request.signature, request.public_key)
            .await
            .map_err(|e| SparkClientError::SignatureVerification(e.into()))
    }

    pub async fn build_auth_payload(
        username: &str,
        timestamp: u64,
    ) -> Result<SignedAuthPayload, SparkClientError> {
        let (signer, pubkey) = test_identity(42).await?;
        let (to_signer, to_pubkey) = test_identity(43).await?;

        let register_signature = sign(&signer, format!("{username}-{timestamp}")).await?;
        let recover_signature = sign(&signer, format!("{pubkey}-{timestamp}")).await?;
        let to_register_signature = sign(&to_signer, format!("{username}-{timestamp}")).await?;
        let to_recover_signature = sign(&to_signer, format!("{to_pubkey}-{timestamp}")).await?;
        let transfer_message = format!("transfer:{username}-{to_pubkey}");
        let transfer_from_signature = sign(&signer, transfer_message.clone()).await?;
        let transfer_to_signature = sign(&to_signer, transfer_message).await?;

        Ok(SignedAuthPayload {
            pubkey,
            timestamp,
            register_signature: register_signature.clone(),
            recover_signature,
            unregister_signature: register_signature,
            to_pubkey,
            to_register_signature,
            to_recover_signature,
            transfer_from_signature,
            transfer_to_signature,
        })
    }

    /// v2 signatures by the identities [`Self::build_auth_payload`] uses, over
    /// the messages a Breez SDK 0.23+ client addressing `domain` signs.
    pub async fn build_v2_auth_payload(
        username: &str,
        timestamp: u64,
        domain: &str,
        description: &str,
    ) -> Result<SignedV2AuthPayload, SparkClientError> {
        let (signer, pubkey) = test_identity(42).await?;
        let (to_signer, to_pubkey) = test_identity(43).await?;

        Ok(SignedV2AuthPayload {
            domain: domain.to_string(),
            description: description.to_string(),
            available_signature: sign(
                &signer,
                signed_message::available(domain, &pubkey, username, timestamp),
            )
            .await?,
            register_signature: sign(
                &signer,
                signed_message::register(domain, username, description, timestamp),
            )
            .await?,
            unregister_signature: sign(
                &signer,
                signed_message::unregister(domain, username, timestamp),
            )
            .await?,
            recover_signature: sign(&signer, signed_message::recover(domain, &pubkey, timestamp))
                .await?,
            metadata_signature: sign(
                &signer,
                signed_message::metadata(domain, &pubkey, timestamp),
            )
            .await?,
            to_recover_signature: sign(
                &to_signer,
                signed_message::recover(domain, &to_pubkey, timestamp),
            )
            .await?,
            transfer_from_signature: sign(
                &signer,
                signed_message::transfer_from(domain, username, &pubkey, &to_pubkey, timestamp),
            )
            .await?,
            transfer_to_signature: sign(
                &to_signer,
                signed_message::transfer_to(
                    domain,
                    username,
                    &pubkey,
                    &to_pubkey,
                    description,
                    timestamp,
                ),
            )
            .await?,
        })
    }

    pub async fn register_wallet_webhook(
        &self,
        request: WebhookRegistrationRequest,
    ) -> Result<String, SparkClientError> {
        crate::webhook::register_wallet_webhook(Arc::clone(&self.service_provider), request).await
    }
}

/// A deterministic regtest identity and its hex pubkey.
async fn test_identity(seed: u8) -> Result<(DefaultSigner, String), SparkClientError> {
    let signer = DefaultSigner::new(&[seed; 32], spark_wallet::Network::Regtest)
        .map_err(|e| SparkClientError::Signing(e.into()))?;
    let pubkey = signer
        .get_identity_public_key()
        .await
        .map_err(|e| SparkClientError::Signing(e.into()))?
        .to_string();
    Ok((signer, pubkey))
}

async fn sign(signer: &DefaultSigner, message: String) -> Result<String, SparkClientError> {
    let signature = signer
        .sign_message_ecdsa_with_identity_key(message.as_bytes())
        .await
        .map_err(|e| SparkClientError::Signing(e.into()))?;
    Ok(hex::encode(signature.serialize_der()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deterministic_auth_payload_has_expected_shape() {
        let payload = Client::build_auth_payload("alice", 1).await.unwrap();

        assert!(!payload.pubkey.is_empty());
        assert!(!payload.to_pubkey.is_empty());
        assert_ne!(payload.pubkey, payload.to_pubkey);
        assert!(!payload.register_signature.is_empty());
        assert!(!payload.recover_signature.is_empty());
        assert!(!payload.unregister_signature.is_empty());
        assert!(!payload.to_register_signature.is_empty());
        assert!(!payload.to_recover_signature.is_empty());
        assert!(!payload.transfer_from_signature.is_empty());
        assert!(!payload.transfer_to_signature.is_empty());
    }

    #[tokio::test]
    async fn v2_auth_payload_signs_distinct_messages_for_the_same_identities() {
        let legacy = Client::build_auth_payload("alice", 1).await.unwrap();
        let v2 = Client::build_v2_auth_payload("alice", 1, "localhost:8080", "d")
            .await
            .unwrap();

        assert_ne!(v2.register_signature, legacy.register_signature);
        assert_ne!(v2.unregister_signature, v2.register_signature);
        assert_ne!(v2.recover_signature, v2.metadata_signature);
        assert_ne!(v2.recover_signature, legacy.recover_signature);
        assert_ne!(v2.transfer_from_signature, v2.transfer_to_signature);
    }
}
