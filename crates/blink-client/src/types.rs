#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    endpoint: String,
}

impl ClientConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    pub fn production() -> Self {
        Self::new(crate::PRODUCTION_GRAPHQL_ENDPOINT)
    }

    pub fn staging() -> Self {
        Self::new(crate::STAGING_GRAPHQL_ENDPOINT)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateInvoiceRequest<'a> {
    pub wallet_id: &'a str,
    pub amount_sat: u64,
    pub description_hash_hex: Option<String>,
    pub expires_in_minutes: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedInvoice {
    pub bolt11: String,
    pub payment_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatusState {
    Paid,
    Pending,
    Expired,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentStatus {
    pub state: PaymentStatusState,
    pub settled: bool,
    pub payment_hash: String,
    pub payment_request: Option<String>,
    pub preimage: Option<String>,
    pub amount_received_sat: Option<i64>,
}
