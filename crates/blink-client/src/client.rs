use serde::Deserialize;
use serde_json::json;

use crate::error::{BlinkClientError, GraphqlError};
use crate::types::{ClientConfig, CreateInvoiceRequest, CreatedInvoice};

pub const PRODUCTION_GRAPHQL_ENDPOINT: &str = "https://api.blink.sv/graphql";
pub const STAGING_GRAPHQL_ENDPOINT: &str = "https://api.staging.blink.sv/graphql";

const BTC_INVOICE_OPERATION: &str =
    include_str!("../graphql/ln_invoice_create_on_behalf_of_recipient.graphql");
const USD_INVOICE_OPERATION: &str =
    include_str!("../graphql/ln_usd_invoice_btc_denominated_create_on_behalf_of_recipient.graphql");

#[derive(Debug, Clone)]
pub struct Client {
    config: ClientConfig,
    http_client: reqwest::Client,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Self::with_http_client(config, reqwest::Client::new())
    }

    pub fn with_http_client(config: ClientConfig, http_client: reqwest::Client) -> Self {
        Self {
            config,
            http_client,
        }
    }

    pub async fn create_btc_invoice(
        &self,
        request: CreateInvoiceRequest<'_>,
    ) -> Result<CreatedInvoice, BlinkClientError> {
        let data = self
            .execute::<BtcInvoiceData>(BTC_INVOICE_OPERATION, request)
            .await?;
        data.ln_invoice_create_on_behalf_of_recipient
            .into_created_invoice()
    }

    pub async fn create_usd_invoice(
        &self,
        request: CreateInvoiceRequest<'_>,
    ) -> Result<CreatedInvoice, BlinkClientError> {
        let data = self
            .execute::<UsdInvoiceData>(USD_INVOICE_OPERATION, request)
            .await?;
        data.ln_usd_invoice_btc_denominated_create_on_behalf_of_recipient
            .into_created_invoice()
    }

    async fn execute<T>(
        &self,
        query: &'static str,
        request: CreateInvoiceRequest<'_>,
    ) -> Result<T, BlinkClientError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = self
            .http_client
            .post(self.config.endpoint())
            .json(&json!({
                "query": query,
                "variables": {
                    "input": {
                        "recipientWalletId": request.wallet_id,
                        "amount": request.amount_sat,
                        "descriptionHash": request.description_hash_hex,
                        "expiresIn": request.expires_in_minutes,
                    }
                }
            }))
            .send()
            .await?
            .error_for_status()?;

        let envelope = response.json::<GraphqlEnvelope<T>>().await?;
        if !envelope.errors.is_empty() {
            return Err(BlinkClientError::Graphql(envelope.errors));
        }

        envelope
            .data
            .ok_or(BlinkClientError::MalformedResponse("missing GraphQL data"))
    }
}

#[derive(Debug, Deserialize)]
struct GraphqlEnvelope<T> {
    data: Option<T>,
    #[serde(default)]
    errors: Vec<GraphqlError>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BtcInvoiceData {
    ln_invoice_create_on_behalf_of_recipient: InvoicePayload,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsdInvoiceData {
    ln_usd_invoice_btc_denominated_create_on_behalf_of_recipient: InvoicePayload,
}

#[derive(Debug, Deserialize)]
struct InvoicePayload {
    invoice: Option<GraphqlInvoice>,
    #[serde(default)]
    errors: Vec<GraphqlError>,
}

impl InvoicePayload {
    fn into_created_invoice(self) -> Result<CreatedInvoice, BlinkClientError> {
        if !self.errors.is_empty() {
            return Err(BlinkClientError::ApiFailure(
                self.errors
                    .into_iter()
                    .map(|error| error.message)
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }

        let Some(invoice) = self.invoice else {
            return Err(BlinkClientError::MalformedResponse(
                "missing invoice payload",
            ));
        };
        let Some(bolt11) = invoice.payment_request else {
            return Err(BlinkClientError::MalformedResponse(
                "missing invoice paymentRequest",
            ));
        };
        let Some(payment_hash) = invoice.payment_hash else {
            return Err(BlinkClientError::MalformedResponse(
                "missing invoice paymentHash",
            ));
        };

        Ok(CreatedInvoice {
            bolt11,
            payment_hash,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphqlInvoice {
    payment_request: Option<String>,
    payment_hash: Option<String>,
}
