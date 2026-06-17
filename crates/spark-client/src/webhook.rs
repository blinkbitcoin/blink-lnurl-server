use std::sync::Arc;

use spark::ssp::{ServiceProvider, SparkWalletWebhookEventType};

use crate::error::SparkClientError;
use crate::types::WebhookRegistrationRequest;

pub async fn register_wallet_webhook(
    service_provider: Arc<ServiceProvider>,
    request: WebhookRegistrationRequest,
) -> Result<String, SparkClientError> {
    service_provider
        .register_wallet_webhook(
            &request.webhook_url,
            &request.secret,
            vec![SparkWalletWebhookEventType::SparkLightningReceiveFinished],
        )
        .await
        .map_err(|e| SparkClientError::WebhookRegistration(e.into()))
}

#[cfg(test)]
mod tests {}
