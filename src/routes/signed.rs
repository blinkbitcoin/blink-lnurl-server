//! Signature verification for the `/lnurlpay/{pubkey}` management routes.
//!
//! A route lists the messages a signature may cover, most-preferred first:
//! the `breez-lnurl:v2` form Breez SDK 0.23+ signs, or the `blink-lnurl:v1`
//! form the Blink app signs itself, then the pre-v2 form older clients still
//! send. The first one that verifies wins, and the route reads
//! which format matched from the returned [`Candidate`].
//!
//! Pre-v2 verifies are counted per route and logged once a minute on
//! [`LEGACY_SIGNATURE_TARGET`]; those counts reading zero is what gates
//! dropping the legacy candidates.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{Json, http::StatusCode};
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::secp256k1::{PublicKey, ecdsa::Signature};
use serde_json::Value;
use tracing::{debug, error, info, trace};

use crate::{
    repository::{LnurlRepository, StatementClaim},
    state::State,
    time::{now, now_u64},
};

use super::account::{parse_pubkey, verify_with_spark_client};

type ApiError = (StatusCode, Json<Value>);

/// Target the legacy-usage line is logged on, so a deployment can route it
/// somewhere durable without keeping the rest of the route output.
pub const LEGACY_SIGNATURE_TARGET: &str = "blink_lnurl::legacy_signatures";
const LEGACY_REPORT_INTERVAL: Duration = Duration::from_mins(1);
/// How often expired signed-message claims are pruned.
const CLAIM_PRUNE_INTERVAL: Duration = Duration::from_mins(10);

/// The route a signature authorizes, which names its legacy counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignedRoute {
    /// v2-only: the route is new, so it has no legacy form and no counter.
    Available,
    Register,
    /// v2-only: the legacy unregister message is the legacy register message,
    /// so accepting it would let a register signature delete the address.
    Unregister,
    /// v2-only: the legacy transfer message carries no time or domain, so a
    /// signature over it would authorize the handover on any deployment,
    /// indefinitely.
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
    const LEGACY: [Self; 7] = [
        Self::Register,
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
            Self::Available | Self::Unregister | Self::Transfer => None,
            Self::Register => Some(0),
            Self::Recover => Some(1),
            Self::Metadata => Some(2),
            Self::Mode => Some(3),
            Self::ZapReceipt => Some(4),
            Self::InvoicePaid => Some(5),
            Self::InvoicesPaid => Some(6),
        }
    }
}

/// Which wire format a candidate message is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MessageFormat {
    /// `breez-lnurl:v2`, built by `lnurl-models`.
    BreezV2,
    /// `blink-lnurl:v1`, the Blink app's own messages.
    BlinkV1,
    /// Pre-v2: `{message}-{timestamp}`.
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

    pub(super) fn blink_v1(message: String, route: SignedRoute) -> Self {
        Self {
            message,
            route,
            format: MessageFormat::BlinkV1,
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

/// When the claim over a statement signed at `timestamp` may be pruned: once
/// [`check_timestamp`] refuses the statement on its own. Saturating, since an
/// unrepresentable expiry only retains the claim longer.
fn claim_expires_at(timestamp: u64) -> i64 {
    i64::try_from(timestamp.saturating_add(super::ACCEPTABLE_TIME_DIFF_SECS)).unwrap_or(i64::MAX)
}

/// The claim record for the statement `candidate` authorized on `domain`.
///
/// Hashes what was authorized rather than the signature bytes: ECDSA
/// signatures are malleable, so keying on them would let a reshaped signature
/// re-authorize a claimed statement. The resolved domain is hashed in even
/// though v2 messages already name it: legacy messages do not, and without it
/// presenting a legacy statement on another allowlisted host would spend it
/// for the host it was meant for.
pub(super) fn statement_claim(
    pubkey: &PublicKey,
    domain: &str,
    candidate: &Candidate,
    timestamp: u64,
) -> StatementClaim {
    let mut engine = sha256::Hash::engine();
    engine.input(pubkey.to_string().as_bytes());
    // Every field is delimited so no pubkey/domain/message split can be read
    // two ways; a domain cannot contain NUL.
    engine.input(b"\x00");
    engine.input(domain.as_bytes());
    engine.input(b"\x00");
    engine.input(candidate.message.as_bytes());
    StatementClaim {
        statement_hash: sha256::Hash::from_engine(engine).to_byte_array(),
        route: candidate.route.as_str(),
        expires_at: claim_expires_at(timestamp),
    }
}

/// The response to a statement that was already acted on. Routes never claim
/// on their own: the claim rides in the transaction of the write it
/// authorizes, so a write that fails rolls it back and a client that retries
/// a refused request is not told its signature was used.
pub(super) fn statement_already_used() -> ApiError {
    (
        StatusCode::CONFLICT,
        Json(Value::String("signature has already been used".into())),
    )
}

/// Prune expired claims periodically. Retention is tied to the accept window:
/// a claim is only dropped once its statement's timestamp is refused anyway.
pub fn spawn_signed_message_pruner<DB>(db: DB)
where
    DB: LnurlRepository + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLAIM_PRUNE_INTERVAL);
        loop {
            interval.tick().await;
            match db.delete_expired_signed_messages(now()).await {
                Ok(0) => {}
                Ok(count) => debug!("pruned {count} expired signed-message claims"),
                Err(e) => error!("failed to prune signed-message claims: {e}"),
            }
        }
    });
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
        for route in [
            SignedRoute::Available,
            SignedRoute::Unregister,
            SignedRoute::Transfer,
        ] {
            assert_eq!(route.legacy_index(), None, "{} is v2-only", route.as_str());
        }
    }

    #[test]
    fn statement_claims_key_on_pubkey_domain_and_message_not_signature() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let key = |seed| {
            let secret = bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
            PublicKey::from_secret_key(&secp, &secret)
        };
        let message = |text: &str| Candidate::legacy(text.to_string(), SignedRoute::Register);
        let claim = |seed, domain, text| statement_claim(&key(seed), domain, &message(text), 1);

        assert_eq!(
            claim(1, "a.example", "alice-1"),
            claim(1, "a.example", "alice-1")
        );
        for other in [
            claim(2, "a.example", "alice-1"),
            claim(1, "b.example", "alice-1"),
            claim(1, "a.example", "alice-2"),
        ] {
            assert_ne!(
                claim(1, "a.example", "alice-1").statement_hash,
                other.statement_hash
            );
        }
    }

    #[test]
    fn claim_expiry_outlives_the_accept_window() {
        assert_eq!(claim_expires_at(1_000), 1_600);
        assert_eq!(claim_expires_at(u64::MAX), i64::MAX);
    }

    #[test]
    fn legacy_message_appends_the_timestamp() {
        assert_eq!(
            legacy_timestamped("alice", 1_700_000_000),
            "alice-1700000000"
        );
    }
}
