use async_graphql::{Context, EmptySubscription, InputObject, Object, Schema, SimpleObject};
use std::marker::PhantomData;

use super::auth::AuthSubject;
use crate::{
    ln_address::{self, LnAddressError},
    repository::{AccountProvider, LnurlRepository},
    state::State,
    webhooks::WebhookRepository,
};

pub type LnurlSchema<DB> = Schema<QueryRoot<DB>, MutationRoot<DB>, EmptySubscription>;

// Custom scalars matching the public subgraph's contract. Defined locally so
// the supergraph composes them as this subgraph's own scalars.
macro_rules! string_scalar {
    ($name:ident) => {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        async_graphql::scalar!($name);
    };
}

string_scalar!(PaymentHash);
string_scalar!(LnPaymentRequest);
string_scalar!(LnPaymentPreImage);
string_scalar!(Username);

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SatAmount(pub u64);

async_graphql::scalar!(SatAmount);

/// Application error surfaced in a mutation payload (mirrors the shape clients
/// expect from the blinkbitcoin/blink#767 reference without sharing the core
/// subgraph's `Error` interface).
#[derive(SimpleObject)]
pub struct LnAddressErrorObject {
    pub code: Option<String>,
    pub message: String,
}

#[derive(SimpleObject)]
pub struct LnAddressInvoice {
    pub payment_hash: PaymentHash,
    /// BOLT-11 payment request to be paid to the lightning address.
    pub payment_request: LnPaymentRequest,
    /// LUD-21 verify url. Prefer the `lnAddressInvoicePaymentStatus` query with
    /// the paymentHash to check settlement.
    pub verify: String,
}

#[derive(SimpleObject)]
pub struct LnAddressInvoicePayload {
    pub errors: Vec<LnAddressErrorObject>,
    pub invoice: Option<LnAddressInvoice>,
}

#[derive(SimpleObject)]
pub struct LnAddressInvoicePaymentStatus {
    /// Whether the invoice has been paid.
    pub settled: bool,
    /// Payment preimage, present once the invoice is settled.
    pub preimage: Option<LnPaymentPreImage>,
}

#[derive(SimpleObject)]
pub struct AccountIdentifier {
    /// Whether a Blink account exists for the given username.
    pub exists: bool,
    /// The backing provider of the account (blink or spark). Null when the
    /// account does not exist.
    pub provider: Option<AccountProviderType>,
}

#[derive(async_graphql::Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(name = "AccountProvider")]
pub enum AccountProviderType {
    Blink,
    Spark,
}

impl From<AccountProvider> for AccountProviderType {
    fn from(provider: AccountProvider) -> Self {
        match provider {
            AccountProvider::Blink => AccountProviderType::Blink,
            AccountProvider::Spark => AccountProviderType::Spark,
        }
    }
}

#[derive(InputObject)]
pub struct LnAddressInvoiceCreateInput {
    /// Blink lightning address to create an invoice for (user@domain).
    pub ln_address: String,
    /// Amount in satoshis.
    pub amount: SatAmount,
}

#[derive(InputObject)]
pub struct LnAddressInvoicePaymentStatusInput {
    /// Payment hash of the invoice created via `lnAddressInvoiceCreate`.
    pub payment_hash: PaymentHash,
}

pub struct QueryRoot<DB>(pub PhantomData<DB>);

#[Object(name = "Query")]
impl<DB> QueryRoot<DB>
where
    DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
{
    /// Settlement status of an invoice created via `lnAddressInvoiceCreate`.
    /// Blink recipients settle-on-read; Spark recipients read-from-store
    /// (settlement is SSP-webhook-driven). Available on the signed anonymous
    /// gateway path.
    async fn ln_address_invoice_payment_status(
        &self,
        ctx: &Context<'_>,
        input: LnAddressInvoicePaymentStatusInput,
    ) -> async_graphql::Result<LnAddressInvoicePaymentStatus> {
        let state = ctx.data::<State<DB>>()?;
        let status = ln_address::ln_address_invoice_status(state, &input.payment_hash.0)
            .await
            .map_err(to_graphql_error)?;
        Ok(LnAddressInvoicePaymentStatus {
            settled: status.settled,
            preimage: status.preimage.map(LnPaymentPreImage),
        })
    }

    /// Resolve a Blink lightning address username to `{ exists, provider }`.
    async fn account_identifier(
        &self,
        ctx: &Context<'_>,
        username: Username,
    ) -> async_graphql::Result<AccountIdentifier> {
        let state = ctx.data::<State<DB>>()?;
        let domain = default_domain(state).await;
        let result = ln_address::account_identifier_for_username(state, &domain, &username.0)
            .await
            .map_err(to_graphql_error)?;
        Ok(AccountIdentifier {
            exists: result.exists,
            provider: result.provider.map(AccountProviderType::from),
        })
    }
}

pub struct MutationRoot<DB>(pub PhantomData<DB>);

#[Object(name = "Mutation")]
impl<DB> MutationRoot<DB>
where
    DB: LnurlRepository + WebhookRepository + Clone + Send + Sync + 'static,
{
    /// Returns a lightning invoice for a Blink lightning address. Works for
    /// both custodial and non-custodial (Spark) recipients. Requires an
    /// authenticated session or an API/OAuth token with `receive` or `write`.
    async fn ln_address_invoice_create(
        &self,
        ctx: &Context<'_>,
        input: LnAddressInvoiceCreateInput,
    ) -> async_graphql::Result<LnAddressInvoicePayload> {
        if let Some(err) = require_receive_auth(ctx) {
            return Ok(err);
        }
        let amount_sat = input.amount.0;
        if amount_sat == 0 {
            return Ok(error_payload(
                "INVALID_INPUT",
                "amount must be a positive satoshi amount".to_string(),
            ));
        }

        let state = ctx.data::<State<DB>>()?;
        match ln_address::create_invoice_for_ln_address(state, &input.ln_address, amount_sat).await
        {
            Ok(invoice) => Ok(LnAddressInvoicePayload {
                errors: vec![],
                invoice: Some(LnAddressInvoice {
                    payment_hash: PaymentHash(invoice.payment_hash),
                    payment_request: LnPaymentRequest(invoice.payment_request),
                    verify: invoice.verify_url,
                }),
            }),
            Err(e) => Ok(error_payload(error_code(&e), e.to_string())),
        }
    }
}

fn require_receive_auth(ctx: &Context<'_>) -> Option<LnAddressInvoicePayload> {
    let Some(subject) = ctx.data_opt::<AuthSubject>() else {
        return Some(error_payload(
            "NOT_AUTHORIZED",
            "authentication required".to_string(),
        ));
    };
    // Interactive sessions carry no scope claim; API/OAuth tokens carry
    // `receive` or `write`. Anonymous gateway subjects are rejected.
    let authed = !subject.is_anonymous()
        && (subject.has_scope("receive")
            || subject.has_scope("write")
            || subject.scopes.is_empty());
    if authed {
        None
    } else {
        Some(error_payload(
            "NOT_AUTHORIZED",
            "not authorized to execute this mutation".to_string(),
        ))
    }
}

fn error_payload(code: &str, message: String) -> LnAddressInvoicePayload {
    LnAddressInvoicePayload {
        errors: vec![LnAddressErrorObject {
            code: Some(code.to_string()),
            message,
        }],
        invoice: None,
    }
}

fn error_code(err: &LnAddressError) -> &'static str {
    match err {
        LnAddressError::InvalidIdentifier(_) => "INVALID_IDENTIFIER",
        LnAddressError::NotFound => "NOT_FOUND",
        LnAddressError::UnsupportedDomain => "UNSUPPORTED_DOMAIN",
        LnAddressError::AmountOutOfRange => "AMOUNT_OUT_OF_RANGE",
        LnAddressError::InvoiceCreationFailed => "INVOICE_CREATION_FAILED",
        LnAddressError::Internal => "INTERNAL_ERROR",
    }
}

#[allow(clippy::needless_pass_by_value)]
fn to_graphql_error(err: LnAddressError) -> async_graphql::Error {
    async_graphql::Error::new(err.to_string())
}

async fn default_domain<DB>(state: &State<DB>) -> String {
    let domains = state.domains.read().await;
    domains.iter().next().cloned().unwrap_or_default()
}
