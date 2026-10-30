//! Signature verification for the `/lnurlpay/{pubkey}` management routes.
//!
//! A route lists the messages a signature may cover, most-preferred first:
//! the `breez-lnurl:v2` form Breez SDK 0.23+ signs, then the pre-v2 form older
//! clients still send. The first one that verifies wins, and the route reads
//! which format matched from the returned [`Candidate`].
//!
//! Pre-v2 verifies are counted per route and logged once a minute on
//! [`LEGACY_SIGNATURE_TARGET`]; those counts reading zero is what gates
//! dropping the legacy candidates.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{Json, http::StatusCode};
use bitcoin::secp256k1::{PublicKey, ecdsa::Signature};
use serde_json::Value;
use tracing::{info, trace};

use crate::{state::State, time::now_u64};

use super::account::{parse_pubkey, verify_with_spark_client};

type ApiError = (StatusCode, Json<Value>);

/// Target the legacy-usage line is logged on, so a deployment can route it
/// somewhere durable without keeping the rest of the route output.
pub const LEGACY_SIGNATURE_TARGET: &str = "blink_lnurl::legacy_signatures";
const LEGACY_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// The route a signature authorizes, which names its legacy counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignedRoute {
    /// v2-only: the route is new, so it has no legacy form and no counter.
    Available,
    Register,
    Unregister,
    Transfer,
    Recover,
    Metadata,
    Mode,
    ZapReceipt,
    InvoicePaid,
    InvoicesPaid,
}

impl SignedRoute {
    /// Every route that still accepts a legacy message, in report order.
    const LEGACY: [Self; 9] = [
        Self::Register,
        Self::Unregister,
        Self::Transfer,
        Self::Recover,
        Self::Metadata,
        Self::Mode,
        Self::ZapReceipt,
        Self::InvoicePaid,
        Self::InvoicesPaid,
    ];

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Register => "register",
            Self::Unregister => "unregister",
            Self::Transfer => "transfer",
            Self::Recover => "recover",
            Self::Metadata => "metadata",
            Self::Mode => "mode",
            Self::ZapReceipt => "zap_receipt",
            Self::InvoicePaid => "invoice_paid",
            Self::InvoicesPaid => "invoices_paid",
        }
    }

    const fn legacy_index(self) -> Option<usize> {
        match self {
            Self::Available => None,
            Self::Register => Some(0),
            Self::Unregister => Some(1),
            Self::Transfer => Some(2),
            Self::Recover => Some(3),
            Self::Metadata => Some(4),
            Self::Mode => Some(5),
            Self::ZapReceipt => Some(6),
            Self::InvoicePaid => Some(7),
            Self::InvoicesPaid => Some(8),
        }
    }
}

/// Which wire format a candidate message is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MessageFormat {
    /// `breez-lnurl:v2`, built by `lnurl-models`.
    BreezV2,
    /// Pre-v2: `{message}-{timestamp}`, or the untimestamped transfer message.
    Legacy,
}

/// A message a signature may cover.
#[derive(Debug)]
pub(super) struct Candidate {
    pub(super) message: String,
    pub(super) route: SignedRoute,
    pub(super) format: MessageFormat,
}

impl Candidate {
    pub(super) fn breez_v2(message: String, route: SignedRoute) -> Self {
        Self {
            message,
            route,
            format: MessageFormat::BreezV2,
        }
    }

    pub(super) fn legacy(message: String, route: SignedRoute) -> Self {
        Self {
            message,
            route,
            format: MessageFormat::Legacy,
        }
    }
}

/// Append the timestamp the way every pre-v2 message did.
pub(super) fn legacy_timestamped(message: &str, timestamp: u64) -> String {
    format!("{message}-{timestamp}")
}

/// Parse the identity pubkey and DER signature a signed request carries.
/// Independent of the message the signature covers.
pub(super) fn parse_signed_request(
    pubkey: &str,
    signature: &str,
) -> Result<(PublicKey, Signature), ApiError> {
    let pubkey = parse_pubkey(pubkey)?;
    let signature = hex::decode(signature).map_err(|e| {
        trace!("invalid signature, could not decode: {}", e);
        invalid_signature()
    })?;
    let signature = Signature::from_der(&signature).map_err(|e| {
        trace!("invalid signature, could not parse: {:?}", e);
        invalid_signature()
    })?;
    Ok((pubkey, signature))
}

/// Refuse a timestamp outside the accept window, bounded symmetrically so a
/// device whose clock runs fast still works.
pub(super) fn check_timestamp(timestamp: u64) -> Result<(), ApiError> {
    let now = now_u64();
    let diff = timestamp.abs_diff(now);
    if diff > super::ACCEPTABLE_TIME_DIFF_SECS {
        trace!(
            "invalid timestamp, too far off: {}, now: {}, diff: {}",
            timestamp, now, diff
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid timestamp".into())),
        ));
    }
    Ok(())
}

/// Verify `signature` against each candidate, accepting the first match.
///
/// `domain` is the resolved request domain on routes whose v2 message names
/// it. A miss there names it back, which separates "signed for another
/// domain" (a proxy rewriting `Host`) from "not signed by this key"; the
/// caller chose the header that resolved to it, so this tells it nothing new.
pub(super) async fn verify_candidates<'a, DB>(
    state: &State<DB>,
    pubkey: &PublicKey,
    signature: &Signature,
    candidates: &'a [Candidate],
    domain: Option<&str>,
) -> Result<&'a Candidate, ApiError> {
    for candidate in candidates {
        let request = spark_client::VerifyMessageRequest {
            message: &candidate.message,
            signature,
            public_key: pubkey,
        };
        if verify_with_spark_client(state, request).await.is_ok() {
            if candidate.format == MessageFormat::Legacy {
                record_legacy_verify(candidate.route);
            }
            return Ok(candidate);
        }
    }

    if let Some(domain) = domain {
        trace!("invalid signature, no candidate message verified for domain '{domain}'");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Value::String(format!(
                "invalid signature for domain '{domain}'"
            ))),
        ));
    }
    trace!("invalid signature, no candidate message verified");
    Err(invalid_signature())
}

fn invalid_signature() -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(Value::String("invalid signature".into())),
    )
}

/// Legacy verifies since the last report, per route.
///
/// Counted rather than logged per verify: these paths are reachable without a
/// valid identity, so a line per verify would be caller-driven log volume.
static LEGACY_VERIFIES: [AtomicU64; SignedRoute::LEGACY.len()] =
    [const { AtomicU64::new(0) }; SignedRoute::LEGACY.len()];

fn record_legacy_verify(route: SignedRoute) {
    if let Some(index) = route.legacy_index() {
        LEGACY_VERIFIES[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// Take and reset the counts, one entry per route including the zeroes: a
/// route missing from the report cannot be told apart from one that has
/// stopped seeing legacy traffic.
fn drain_legacy_verifies() -> Vec<(&'static str, u64)> {
    SignedRoute::LEGACY
        .iter()
        .filter_map(|route| {
            let index = route.legacy_index()?;
            Some((
                route.as_str(),
                LEGACY_VERIFIES[index].swap(0, Ordering::Relaxed),
            ))
        })
        .collect()
}

/// Log the legacy counts once per interval.
pub fn spawn_legacy_signature_reporter() {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(LEGACY_REPORT_INTERVAL).await;
            let counts: Vec<String> = drain_legacy_verifies()
                .into_iter()
                .map(|(route, count)| format!("{route}={count}"))
                .collect();
            info!(
                target: LEGACY_SIGNATURE_TARGET,
                "legacy signed-message verifies: {}",
                counts.join(" ")
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_legacy_route_has_its_own_counter() {
        let mut seen = [false; SignedRoute::LEGACY.len()];
        for route in SignedRoute::LEGACY {
            let index = route.legacy_index().expect("legacy route has a counter");
            assert!(!seen[index], "{} shares a counter", route.as_str());
            seen[index] = true;
        }
        assert_eq!(SignedRoute::Available.legacy_index(), None);
    }

    #[test]
    fn legacy_message_appends_the_timestamp() {
        assert_eq!(
            legacy_timestamped("alice", 1_700_000_000),
            "alice-1700000000"
        );
    }
}
