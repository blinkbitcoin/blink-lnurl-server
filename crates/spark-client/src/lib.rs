mod client;
mod error;
mod types;
mod webhook;

pub use client::Client;
pub use error::SparkClientError;
pub use spark_wallet::Network;
pub use types::{
    ClientConfig, CreateInvoiceRequest, CreatedInvoice, SignedAuthPayload, SignedV2AuthPayload,
    VerifyMessageRequest, WebhookRegistrationRequest,
};
pub use webhook::register_wallet_webhook;
