use bitcoin::secp256k1::{PublicKey, ecdsa::Signature};
use spark_wallet::Network;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientConfig {
    pub network: Network,
    pub auth_seed: [u8; 32],
}

impl ClientConfig {
    pub const fn new(network: Network, auth_seed: [u8; 32]) -> Self {
        Self { network, auth_seed }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateInvoiceRequest {
    pub amount_sat: u64,
    pub description_hash: [u8; 32],
    pub receiver_pubkey: PublicKey,
    pub expiry_secs: Option<u32>,
    pub include_spark_address: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedInvoice {
    pub bolt11: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyMessageRequest<'a> {
    pub message: &'a str,
    pub signature: &'a Signature,
    pub public_key: &'a PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAuthPayload {
    pub pubkey: String,
    pub timestamp: u64,
    pub register_signature: String,
    pub recover_signature: String,
    pub unregister_signature: String,
    pub to_pubkey: String,
    pub to_register_signature: String,
    pub to_recover_signature: String,
    pub transfer_from_signature: String,
    pub transfer_to_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRegistrationRequest {
    pub webhook_url: String,
    pub secret: String,
}
