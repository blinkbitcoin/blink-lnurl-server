//! Provider-neutral application functions backing the federated GraphQL
//! subgraph. These wrap the same internal call graph as the public LNURL
//! routes (no HTTP self-fetch, no second verify store) so the resolver layer
//! and the REST handlers share a single owner for invoice creation, settlement
//! status, and identifier resolution.

use bitcoin::hashes::{Hash, sha256};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use std::str::FromStr;
use tracing::error;

use crate::{
    invoice_paid::create_provider_invoice_for_account,
    providers::CreateInvoiceRequest,
    repository::{LnurlRepository, ResolvedRecipient},
    routes,
    state::State,
};

/// Result of creating an invoice for a lightning address identifier.
pub struct LnAddressInvoiceResult {
    pub payment_request: String,
    pub payment_hash: String,
    pub verify_url: String,
}

/// Result of a settlement status lookup for a payment hash.
pub struct LnAddressInvoiceStatusResult {
    pub settled: bool,
    pub preimage: Option<String>,
}

/// Result of resolving a lightning address username to an account.
pub struct AccountIdentifierResult {
    pub exists: bool,
    pub provider: Option<crate::repository::AccountProvider>,
}

#[derive(Debug, thiserror::Error)]
pub enum LnAddressError {
    #[error("invalid lightning address: {0}")]
    InvalidIdentifier(String),
    #[error("lightning address not found")]
    NotFound,
    #[error("unsupported lightning address domain")]
    UnsupportedDomain,
    #[error("amount out of range")]
    AmountOutOfRange,
    #[error("invoice creation failed")]
    InvoiceCreationFailed,
    #[error("internal error")]
    Internal,
}

/// Resolve a `{username}@{domain}` lightning address and validate the domain
/// against the server's configured domains.
/// Split and validate a `user@domain` lightning address. Returns the
/// lowercased domain and the username.
fn parse_ln_address(ln_address: &str) -> Result<(&str, String), LnAddressError> {
    let (username, domain) = ln_address
        .split_once('@')
        .ok_or_else(|| LnAddressError::InvalidIdentifier(ln_address.to_string()))?;
    if username.is_empty() || domain.is_empty() {
        return Err(LnAddressError::InvalidIdentifier(ln_address.to_string()));
    }
    Ok((username, domain.to_lowercase()))
}

pub async fn resolve_recipient_for_ln_address<DB>(
    state: &State<DB>,
    ln_address: &str,
) -> Result<ResolvedRecipient, LnAddressError>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    let (username, domain) = parse_ln_address(ln_address)?;
    {
        let domains = state.domains.read().await;
        if !domains.contains(&domain) {
            return Err(LnAddressError::UnsupportedDomain);
        }
    }

    let recipient = state
        .db
        .resolve_recipient_by_identifier(&domain, username)
        .await
        .map_err(|e| {
            error!("failed to resolve recipient for ln address: {e}");
            LnAddressError::Internal
        })?;

    recipient.ok_or(LnAddressError::NotFound)
}

/// Create an invoice for a lightning address. Performs the same validation,
/// provider dispatch, and persistence as the public LNURL callback route.
/// The amount is in whole satoshis.
#[allow(clippy::similar_names)]
pub async fn create_invoice_for_ln_address<DB>(
    state: &State<DB>,
    ln_address: &str,
    amount_sat: u64,
) -> Result<LnAddressInvoiceResult, LnAddressError>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    let recipient = resolve_recipient_for_ln_address(state, ln_address).await?;
    let username = ln_address.split('@').next().unwrap_or_default();

    let amount_msat = amount_sat
        .checked_mul(1000)
        .ok_or(LnAddressError::AmountOutOfRange)?;

    if amount_msat < state.min_sendable || amount_msat > state.max_sendable {
        return Err(LnAddressError::AmountOutOfRange);
    }

    let min_sendable = routes::resolve_min_sendable_for_recipient(state, &recipient).await;
    if amount_msat < min_sendable {
        return Err(LnAddressError::AmountOutOfRange);
    }

    // No wallet modifier in the address => default wallet; no comment/nostr in
    // the GraphQL surface => description hash over the standard metadata.
    let metadata = routes::metadata_for_recipient(&recipient, username);
    let desc_hash = sha256::Hash::hash(metadata.as_bytes());

    let res = state
        .providers
        .create_invoice(CreateInvoiceRequest {
            recipient: &recipient,
            wallet: recipient.default_wallet,
            amount_sat,
            description_hash: desc_hash.to_byte_array(),
            expiry: None,
            include_spark_address: state.include_spark_address,
        })
        .await
        .map_err(|e| {
            error!("provider invoice creation failed for ln address: {e}");
            LnAddressError::InvoiceCreationFailed
        })?;

    let invoice = Bolt11Invoice::from_str(&res.bolt11).map_err(|e| {
        error!("provider returned unparseable invoice: {e}");
        LnAddressError::Internal
    })?;

    if !matches!(invoice.description(), Bolt11InvoiceDescriptionRef::Hash(hash) if hash.0.to_string() == desc_hash.to_string())
    {
        error!("provider returned invoice with unexpected description hash");
        return Err(LnAddressError::Internal);
    }

    let Some(invoice_amount_msat) = invoice.amount_milli_satoshis() else {
        error!("provider returned invoice without an amount");
        return Err(LnAddressError::Internal);
    };
    if invoice_amount_msat != amount_msat {
        error!(
            "provider returned invoice amount {invoice_amount_msat} msat, expected {amount_msat} msat"
        );
        return Err(LnAddressError::Internal);
    }

    let expiry_timestamp = invoice.expires_at().ok_or_else(|| {
        error!("provider returned invoice with invalid expiry");
        LnAddressError::Internal
    })?;
    let invoice_expiry: i64 = i64::try_from(expiry_timestamp.as_secs()).map_err(|e| {
        error!("invoice expiry out of range: {e}");
        LnAddressError::Internal
    })?;

    let payment_hash = invoice.payment_hash().to_string();
    let account_id = recipient.account_id.clone();
    let user_pubkey = recipient.spark_pubkey.as_deref().unwrap_or("").to_string();

    create_provider_invoice_for_account(
        &state.db,
        &payment_hash,
        Some(&account_id),
        Some(recipient.provider),
        Some(res.wallet_kind),
        res.wallet_id.as_deref(),
        res.provider_payment_hash.as_deref(),
        &user_pubkey,
        &res.bolt11,
        invoice_expiry,
        &recipient.domain,
    )
    .await
    .map_err(|e| {
        error!("failed to persist invoice record: {e}");
        LnAddressError::Internal
    })?;

    Ok(LnAddressInvoiceResult {
        payment_request: res.bolt11,
        verify_url: routes::verify_url_for(state, &recipient.domain, &payment_hash),
        payment_hash,
    })
}

/// Look up settlement status for a payment hash.
///
/// Blink recipients: settle-on-read (polls Blink core and persists the
/// preimage). Spark recipients: read-from-store — settlement arrives via the
/// SSP webhook, so the authoritative answer is `preimage IS NOT NULL`. This
/// mirrors the public LUD-21 `/verify/{payment_hash}` semantics exactly.
pub async fn ln_address_invoice_status<DB>(
    state: &State<DB>,
    payment_hash: &str,
) -> Result<LnAddressInvoiceStatusResult, LnAddressError>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    let status = routes::invoice_settlement_status(state, payment_hash).await;
    match status {
        Ok((settled, preimage)) => Ok(LnAddressInvoiceStatusResult { settled, preimage }),
        Err(()) => Err(LnAddressError::NotFound),
    }
}

/// Resolve a lightning address username to `{ exists, provider }`.
pub async fn account_identifier_for_username<DB>(
    state: &State<DB>,
    domain: &str,
    username: &str,
) -> Result<AccountIdentifierResult, LnAddressError>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    let domain = domain.to_lowercase();
    let recipient = state
        .db
        .resolve_recipient_by_identifier(&domain, username)
        .await
        .map_err(|e| {
            error!("failed to resolve identifier: {e}");
            LnAddressError::Internal
        })?;

    Ok(match recipient {
        Some(r) => AccountIdentifierResult {
            exists: true,
            provider: Some(r.provider),
        },
        None => AccountIdentifierResult {
            exists: false,
            provider: None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ln_address_splits_user_and_lowercases_domain() {
        let (user, domain) = parse_ln_address("Alice@Blink.SV").expect("valid address");
        assert_eq!(user, "Alice");
        assert_eq!(domain, "blink.sv");
    }

    #[test]
    fn parse_ln_address_rejects_missing_separator() {
        assert!(matches!(
            parse_ln_address("not-an-address"),
            Err(LnAddressError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn parse_ln_address_rejects_empty_parts() {
        for addr in ["@blink.sv", "alice@", "@"] {
            assert!(matches!(
                parse_ln_address(addr),
                Err(LnAddressError::InvalidIdentifier(_))
            ));
        }
    }
}
