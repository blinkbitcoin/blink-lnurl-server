mod client;
mod error;
mod types;
mod webhook;

pub use client::Client;
pub use error::SparkClientError;
pub use types::{
    ClientConfig, CreateInvoiceRequest, CreatedInvoice, SignedAuthPayload, VerifyMessageRequest,
    WebhookRegistrationRequest,
};
pub use webhook::register_wallet_webhook;
