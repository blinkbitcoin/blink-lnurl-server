use thiserror::Error;

#[derive(Debug, Error)]
pub enum SparkClientError {
    #[error("Spark wallet construction failed: {0}")]
    WalletConstruction(#[source] anyhow::Error),
    #[error("Spark signature verification failed: {0}")]
    SignatureVerification(#[source] anyhow::Error),
    #[error("Spark signing failed: {0}")]
    Signing(#[source] anyhow::Error),
    #[error("Spark invoice creation failed: {0}")]
    InvoiceCreation(#[source] anyhow::Error),
    #[error("Spark webhook registration failed: {0}")]
    WebhookRegistration(#[source] anyhow::Error),
}
