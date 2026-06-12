use serde::{Deserialize, Serialize};

pub const INTERNAL_ERROR_INVALID_REQUEST: &str = "invalid_request";
pub const INTERNAL_ERROR_INVALID_IDENTIFIER: &str = "invalid_identifier";
pub const INTERNAL_ERROR_WALLET_MODIFIER_NOT_ALLOWED: &str = "wallet_modifier_not_allowed";
pub const INTERNAL_ERROR_BLINK_ACCOUNT_EXISTS: &str = "blink_account_exists";
pub const INTERNAL_ERROR_IDENTIFIER_CONFLICT: &str = "identifier_conflict";
pub const INTERNAL_ERROR_INTERNAL_SERVER_ERROR: &str = "internal_server_error";
pub const INTERNAL_ERROR_INVALID_DOMAIN: &str = "invalid_domain";
pub const INTERNAL_ERROR_NOT_FOUND: &str = "not_found";

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBlinkAccountRequest {
    pub domain: String,
    pub blink_account_id: String,
    pub btc_wallet_id: String,
    pub usd_wallet_id: String,
    pub default_wallet: String,
    pub description: String,
    pub identifiers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBlinkAccountResponse {
    pub account_id: String,
    pub provider: String,
    pub blink_account_id: String,
    pub btc_wallet_id: String,
    pub usd_wallet_id: String,
    pub default_wallet: String,
    pub domain: String,
    pub identifiers: Vec<InternalAccountIdentifierResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InternalAccountIdentifierResponse {
    pub identifier: String,
    pub kind: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InternalIdentifierLookupResponse {
    pub provider: String,
    pub account_id: String,
    pub domain: String,
    pub identifier: String,
    pub identifier_kind: String,
    pub description: String,
    pub requested_wallet: Option<String>,
    pub provider_details: InternalProviderDetailsResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InternalTransferToSparkRequest {
    pub domain: String,
    pub identifier: String,
    pub destination_spark_pubkey: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InternalTransferToSparkResponse {
    pub domain: String,
    pub identifier: String,
    pub provider: String,
    pub spark_pubkey: String,
    pub lightning_address: String,
    pub lnurl: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InternalProviderDetailsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spark_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blink_account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btc_wallet_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usd_wallet_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_wallet: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InternalErrorResponse {
    pub error: String,
}

impl InternalErrorResponse {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckUsernameAvailableResponse {
    pub available: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoverLnurlPayRequest {
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoverLnurlPayResponse {
    pub lnurl: String,
    pub lightning_address: String,
    pub username: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterLnurlPayRequest {
    pub username: String,
    pub signature: String,
    pub timestamp: u64,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnregisterLnurlPayRequest {
    pub username: String,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterLnurlPayResponse {
    pub lnurl: String,
    pub lightning_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferLnurlPayRequest {
    pub username: String,
    pub description: String,
    pub from_pubkey: String,
    pub from_signature: String,
    pub to_signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferLnurlPayResponse {
    pub lnurl: String,
    pub lightning_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListMetadataRequest {
    pub signature: String,
    pub timestamp: u64,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
    pub updated_after: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListMetadataResponse {
    pub metadata: Vec<ListMetadataMetadata>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListMetadataMetadata {
    pub payment_hash: String,
    pub account_id: Option<String>,
    pub sender_comment: Option<String>,
    pub nostr_zap_request: Option<String>,
    pub nostr_zap_receipt: Option<String>,
    pub updated_at: i64,
    pub preimage: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishZapReceiptRequest {
    pub signature: String,
    pub timestamp: u64,
    pub zap_receipt: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InvoicePaidRequest {
    pub signature: String,
    pub timestamp: u64,
    pub preimage: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InvoicesPaidRequest {
    pub signature: String,
    pub timestamp: u64,
    pub invoices: Vec<PaidInvoice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaidInvoice {
    pub preimage: String,
    pub invoice: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishZapReceiptResponse {
    pub published: bool,
    pub zap_receipt: String,
}

/// Legacy Spark lookup sanitizer: trim and lowercase without enforcing Blink
/// Core username rules. New create/update validation uses `canonical_spark_username`.
pub fn sanitize_username(username: &str) -> String {
    username.trim().to_lowercase()
}
