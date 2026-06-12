use serde::Deserialize;
use serde_json::json;

use crate::error::{BlinkClientError, GraphqlError};
use crate::types::{
    ClientConfig, CreateInvoiceRequest, CreatedInvoice, PaymentStatus, PaymentStatusState,
};

pub const PRODUCTION_GRAPHQL_ENDPOINT: &str = "https://api.blink.sv/graphql";
pub const STAGING_GRAPHQL_ENDPOINT: &str = "https://api.staging.blink.sv/graphql";

const BTC_INVOICE_OPERATION: &str =
    include_str!("../graphql/ln_invoice_create_on_behalf_of_recipient.graphql");
const USD_INVOICE_OPERATION: &str =
    include_str!("../graphql/ln_usd_invoice_btc_denominated_create_on_behalf_of_recipient.graphql");
const PAYMENT_STATUS_OPERATION: &str =
    include_str!("../graphql/ln_invoice_payment_status_by_hash.graphql");

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

    pub async fn payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentStatus, BlinkClientError> {
        let data = self
            .execute_payment_status(PAYMENT_STATUS_OPERATION, payment_hash)
            .await?;
        data.ln_invoice_payment_status_by_hash.into_payment_status()
    }

    async fn execute<T>(
        &self,
        query: &'static str,
        request: CreateInvoiceRequest<'_>,
    ) -> Result<T, BlinkClientError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut input = serde_json::Map::from_iter([
            ("recipientWalletId".to_string(), json!(request.wallet_id)),
            ("amount".to_string(), json!(request.amount_sat)),
        ]);
        if let Some(description_hash_hex) = request.description_hash_hex {
            input.insert("descriptionHash".to_string(), json!(description_hash_hex));
        }
        if let Some(expires_in_minutes) = request.expires_in_minutes {
            input.insert("expiresIn".to_string(), json!(expires_in_minutes));
        }

        let response = self
            .http_client
            .post(self.config.endpoint())
            .json(&json!({
                "query": query,
                "variables": {
                    "input": input
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

    async fn execute_payment_status(
        &self,
        query: &'static str,
        payment_hash: &str,
    ) -> Result<PaymentStatusData, BlinkClientError> {
        let response = self
            .http_client
            .post(self.config.endpoint())
            .json(&json!({
                "query": query,
                "variables": {
                    "input": {
                        "paymentHash": payment_hash,
                    }
                }
            }))
            .send()
            .await?
            .error_for_status()?;

        let envelope = response
            .json::<GraphqlEnvelope<PaymentStatusData>>()
            .await?;
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
#[serde(rename_all = "camelCase")]
struct PaymentStatusData {
    ln_invoice_payment_status_by_hash: GraphqlPaymentStatus,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphqlPaymentStatus {
    status: Option<String>,
    payment_hash: Option<String>,
    payment_request: Option<String>,
    payment_preimage: Option<String>,
}

impl GraphqlPaymentStatus {
    fn into_payment_status(self) -> Result<PaymentStatus, BlinkClientError> {
        let Some(status) = self.status else {
            return Err(BlinkClientError::MalformedResponse(
                "missing payment status",
            ));
        };
        let Some(payment_hash) = self.payment_hash else {
            return Err(BlinkClientError::MalformedResponse(
                "missing status paymentHash",
            ));
        };
        let state = match status.as_str() {
            "PAID" => PaymentStatusState::Paid,
            "PENDING" => PaymentStatusState::Pending,
            "EXPIRED" => PaymentStatusState::Expired,
            _ => PaymentStatusState::Unknown,
        };

        Ok(PaymentStatus {
            state,
            settled: state == PaymentStatusState::Paid,
            payment_hash,
            payment_request: self.payment_request,
            preimage: self.payment_preimage,
            amount_received_sat: None,
        })
    }
}
