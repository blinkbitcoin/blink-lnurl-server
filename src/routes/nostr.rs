//! NIP-05: mapping nostr keys to DNS-based internet identifiers.
//!
//! Three routes:
//! - `GET /.well-known/nostr.json?name=<local-part>` — public, spec-shaped
//!   lookup. Serves the static overlay first (domain root `_`, official
//!   accounts), then the dynamic registry. Only ever answers the queried
//!   name; unknown names return an uniform 404 so the endpoint doubles as
//!   an existence oracle and nothing more.
//! - `POST /lnurlpay/{pubkey}/nostr` — spark accounts bind their nostr key
//!   via the standard Spark identity-key signature plus a kind-22242 proof
//!   event carrying the account's `lnaddress` tag.
//! - `POST /nostr/blink` — blink (custodial) accounts do the same, authed
//!   by forwarding their Blink session token to the GraphQL `me` query.
//!
//! The proof event is what stops impersonation: registering a nostr pubkey
//! you do not control (i.e. someone else's established nostr identity)
//! fails because the event must be signed by that very key.

use std::collections::HashMap;

use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::Host;
use nostr::{Event, JsonUtil, Kind, TagKind};
use serde_json::Value;
use tracing::{debug, trace, warn};

use crate::country::client_ip;
use crate::models::{
    ERROR_RATE_LIMITED, NostrJsonResponse, RegisterBlinkNostrIdentityRequest,
    RegisterNostrIdentityRequest, RegisterNostrIdentityResponse,
};
use crate::repository::{AccountProvider, LnurlRepository, LnurlRepositoryError};
use crate::routes::{LnurlServer, account};
use crate::state::State;
use crate::time::now_u64;

/// Short cache: verification clients re-fetch rarely, but a short TTL keeps
/// key rotation and handle transfers from lingering after the DB changes.
const NOSTR_JSON_CACHE_CONTROL: &str = "public, max-age=60";
/// nostr kinds accepted as proof-of-key: 22242 (client authentication) and
/// 27235 (website login) — the two kinds the Blink app already produces
/// with an `lnaddress` tag for `BTCPay` provisioning.
const PROOF_KINDS: [Kind; 2] = [Kind::Authentication, Kind::HttpAuth];

impl<DB> LnurlServer<DB>
where
    DB: LnurlRepository + Clone + Send + Sync + 'static,
{
    /// Public NIP-05 lookup: `GET /.well-known/nostr.json?name=<name>`.
    pub async fn handle_nostr_json(
        Host(host): Host,
        Query(params): Query<HashMap<String, String>>,
        headers: HeaderMap,
        Extension(state): Extension<State<DB>>,
    ) -> Result<Response, (StatusCode, Json<Value>)> {
        if !state.nostr_json_rate_limiter.check(client_ip(&headers)) {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(Value::String(ERROR_RATE_LIMITED.into())),
            ));
        }

        let Some(name) = params.get("name").map(String::as_str) else {
            // The spec always sends `name`; without it there is nothing to
            // answer — and we never enumerate the map.
            return Err(not_found());
        };
        if !is_valid_nip05_local_part(name) {
            return Err(not_found());
        }

        // The endpoint is Host-scoped like every other public route (same
        // Host extractor as the LNURL handlers, so proxy deployments resolve
        // the domain identically across sibling routes) — and the check comes
        // BEFORE the static overlay, so a configured name is never served for
        // an unapproved Host (review L1).
        let domain = account::sanitize_domain(&state, &host).await?;

        // Static overlay next: immune to the registration lifecycle and
        // covers service identities (the `_` domain root, official keys).
        // Intentionally global across the served domains (single-domain
        // deployments today); per-domain keying is a follow-up if multi-domain
        // official identities are ever needed.
        if let Some(pubkey) = state.nostr_static_names.get(name) {
            return Ok(nostr_json_response(name, pubkey));
        }

        match state
            .db
            .get_nostr_identity_by_identifier(&domain, name)
            .await
        {
            Ok(Some(identity)) => Ok(nostr_json_response(name, &identity.nostr_pubkey)),
            Ok(None) => Err(not_found()),
            Err(e) => {
                warn!("nostr.json lookup failed for '{name}': {e}");
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Value::String("internal server error".into())),
                ))
            }
        }
    }

    /// Bind a nostr key to a spark account's handle.
    /// Canonical signed message: `nostr:{nostr_pubkey}-{timestamp}`.
    pub async fn register_nostr(
        Path(pubkey): Path<String>,
        Host(host): Host,
        headers: HeaderMap,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<RegisterNostrIdentityRequest>,
    ) -> Result<Json<RegisterNostrIdentityResponse>, (StatusCode, Json<Value>)> {
        account::require_spark_provider_enabled(&state)?;
        if !state.ip_rate_limiter.check(client_ip(&headers)) {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(Value::String(ERROR_RATE_LIMITED.into())),
            ));
        }

        let nostr_pubkey = normalize_nostr_pubkey(&payload.nostr_pubkey)?;
        if payload.nostr_proof.len() > super::MAX_NOSTR_EVENT_SIZE {
            return Err(bad_request("nostr proof too large"));
        }

        let domain = account::sanitize_domain(&state, &host).await?;

        let pubkey = account::validate(
            &pubkey,
            &payload.signature,
            &format!("nostr:{nostr_pubkey}"),
            payload.timestamp,
            &state,
        )
        .await?;

        let spark_account = state
            .db
            .get_account_by_spark_pubkey(&pubkey.to_string())
            .await
            .map_err(account::storage_error)?;
        let Some(spark_account) = spark_account else {
            return Err((
                StatusCode::NOT_FOUND,
                Json(Value::String(
                    "no account registered for this pubkey".into(),
                )),
            ));
        };

        let username = state
            .db
            .get_spark_username_by_pubkey(&domain, &pubkey.to_string())
            .await
            .map_err(account::storage_error)?
            .map(|u| u.username)
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(Value::String(
                        "no username registered for this account on this domain".into(),
                    )),
                )
            })?;

        verify_nostr_identity_proof(
            &payload.nostr_proof,
            &nostr_pubkey,
            &format!("{username}@{domain}"),
            now_u64(),
        )?;

        state
            .db
            .upsert_nostr_identity(&spark_account.account_id, &domain, &nostr_pubkey, &username)
            .await
            .map_err(nostr_write_error)?;

        debug!("registered nostr identity {nostr_pubkey} for {username}@{domain}");
        Ok(Json(RegisterNostrIdentityResponse {
            nip05: format!("{username}@{domain}"),
            username,
            domain,
            nostr_pubkey,
        }))
    }

    /// Bind a nostr key to a blink (custodial) account's handle. Auth is a
    /// Blink session token validated server-side via the GraphQL `me`
    /// query; the username must already be provisioned in the registry by
    /// Blink Core (internal route) — this route never creates identifiers.
    pub async fn register_nostr_blink(
        Host(host): Host,
        headers: HeaderMap,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<RegisterBlinkNostrIdentityRequest>,
    ) -> Result<Json<RegisterNostrIdentityResponse>, (StatusCode, Json<Value>)> {
        require_blink_provider_enabled(&state)?;
        if !state.ip_rate_limiter.check(client_ip(&headers)) {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(Value::String(ERROR_RATE_LIMITED.into())),
            ));
        }

        let nostr_pubkey = normalize_nostr_pubkey(&payload.nostr_pubkey)?;
        if payload.nostr_proof.len() > super::MAX_NOSTR_EVENT_SIZE {
            return Err(bad_request("nostr proof too large"));
        }

        let domain = account::sanitize_domain(&state, &host).await?;

        let Some(token) = bearer_token(&headers) else {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(Value::String("missing bearer token".into())),
            ));
        };

        let me = state
            .providers
            .blink_me(&token)
            .await
            .map_err(|e| match e {
                // Only definitive auth signals answer 401 (round-2 review):
                // HTTP 401/403 or an authenticated query resolving to me:null.
                // Envelope errors may be upstream failures — those are outages.
                blink_client::BlinkClientError::Unauthorized => (
                    StatusCode::UNAUTHORIZED,
                    Json(Value::String("invalid or expired token".into())),
                ),
                error => {
                    debug!("blink me lookup failed: {error}");
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(Value::String("blink api unavailable".into())),
                    )
                }
            })?;
        let username = me.username.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(Value::String("account has no username".into())),
            )
        })?;

        let recipient = state
            .db
            .resolve_recipient_by_identifier(&domain, &username)
            .await
            .map_err(account::storage_error)?;
        let recipient = recipient.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(Value::String(
                    "username not provisioned on this domain".into(),
                )),
            )
        })?;
        if recipient.provider != AccountProvider::Blink {
            return Err((
                StatusCode::CONFLICT,
                Json(Value::String(
                    "username belongs to a non-blink account".into(),
                )),
            ));
        }
        if recipient.identifier != username {
            return Err((
                StatusCode::CONFLICT,
                Json(Value::String("username mismatch".into())),
            ));
        }
        // Fail-closed on a stale/misprovisioned registry: the token's account
        // and the registry's owner of the username must be the same Blink
        // account (review divergence: compare me.id, not just the username).
        if recipient.blink_account_id.as_deref() != Some(me.id.as_str()) {
            return Err((
                StatusCode::CONFLICT,
                Json(Value::String(
                    "registry entry belongs to a different blink account".into(),
                )),
            ));
        }

        verify_nostr_identity_proof(
            &payload.nostr_proof,
            &nostr_pubkey,
            &format!("{username}@{domain}"),
            now_u64(),
        )?;

        state
            .db
            .upsert_nostr_identity(&recipient.account_id, &domain, &nostr_pubkey, &username)
            .await
            .map_err(nostr_write_error)?;

        debug!(
            "registered nostr identity {nostr_pubkey} for blink account {} ({username}@{domain})",
            recipient.account_id
        );
        Ok(Json(RegisterNostrIdentityResponse {
            nip05: format!("{username}@{domain}"),
            username,
            domain,
            nostr_pubkey,
        }))
    }
}

/// Verify a kind-22242/27235 proof event:
/// - valid nostr id + signature by the claimed key
/// - exactly one `lnaddress` tag equal to `username@domain`
/// - `created_at` within the acceptable window of now
pub(super) fn verify_nostr_identity_proof(
    nostr_proof: &str,
    nostr_pubkey: &str,
    expected_lnaddress: &str,
    now: u64,
) -> Result<(), (StatusCode, Json<Value>)> {
    let event = Event::from_json(nostr_proof).map_err(|e| {
        trace!("invalid nostr proof, could not parse: {e}");
        bad_request("invalid nostr proof")
    })?;

    if !PROOF_KINDS.contains(&event.kind) {
        trace!("nostr proof has unexpected kind: {:?}", event.kind);
        return Err(bad_request("nostr proof has unexpected kind"));
    }

    if event.verify().is_err() {
        trace!("nostr proof does not verify");
        return Err(bad_request("invalid nostr proof"));
    }

    // nostr_pubkey is already validated as canonical lowercase hex.
    if event.pubkey.to_hex() != nostr_pubkey {
        trace!("nostr proof signed by a different key than claimed");
        return Err(bad_request("nostr proof key mismatch"));
    }

    if event.created_at.as_secs().abs_diff(now) > super::ACCEPTABLE_TIME_DIFF_SECS {
        trace!(
            "nostr proof timestamp too far off: {}, now: {}",
            event.created_at.as_secs(),
            now
        );
        return Err(bad_request("stale nostr proof"));
    }

    let lnaddress: Vec<&str> = event
        .tags
        .iter()
        .filter(|tag| matches!(tag.kind(), TagKind::Custom(kind) if kind == "lnaddress"))
        .filter_map(|tag| tag.content())
        .collect();
    if lnaddress.as_slice() != [expected_lnaddress] {
        trace!(
            "nostr proof lnaddress tag mismatch: expected {expected_lnaddress}, got {lnaddress:?}"
        );
        return Err(bad_request("nostr proof lnaddress mismatch"));
    }

    Ok(())
}

/// NIP-05 local-part charset: `a-z0-9-_.` (lowercase only, per spec).
/// Shared with the static-overlay config validation in main — keep one truth.
pub(crate) fn is_valid_nip05_local_part(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
}

/// Canonical nostr identity pubkey: exactly 64 lowercase hex chars.
pub(crate) fn is_canonical_nostr_pubkey(hex: &str) -> bool {
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Accept only canonical lowercase 64-char hex x-only pubkeys. Refuse npubs
/// and mixed case: the spec requires lowercase hex in nostr.json.
pub(super) fn normalize_nostr_pubkey(
    nostr_pubkey: &str,
) -> Result<String, (StatusCode, Json<Value>)> {
    let trimmed = nostr_pubkey.trim();
    if is_canonical_nostr_pubkey(trimmed) {
        return Ok(trimmed.to_string());
    }
    trace!("invalid nostr pubkey format: {trimmed:?}");
    Err(bad_request("invalid nostr pubkey"))
}

/// Blink-provider gate for the blink nostr route, mirroring the spark guard
/// (review L2): a deployment that disabled the Blink provider must not mutate
/// NIP-05 state through it.
fn require_blink_provider_enabled<DB>(state: &State<DB>) -> Result<(), (StatusCode, Json<Value>)> {
    if state.providers.blink_enabled() {
        return Ok(());
    }

    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Value::String(
            crate::models::INTERNAL_ERROR_PROVIDER_DISABLED.to_string(),
        )),
    ))
}

/// Map repository write failures: losing ownership of the exact username
/// between proof and write is a conflict, everything else is a storage error.
fn nostr_write_error(error: LnurlRepositoryError) -> (StatusCode, Json<Value>) {
    match error {
        LnurlRepositoryError::InvalidOwnership => (
            StatusCode::CONFLICT,
            Json(Value::String(
                "username is no longer owned by this account".into(),
            )),
        ),
        other => account::storage_error(other),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        // Auth schemes are case-insensitive (RFC 9110 §11.1): accept
        // `bearer`/`BEARER` alike.
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

fn nostr_json_response(name: &str, pubkey: &str) -> Response {
    let mut names = std::collections::BTreeMap::new();
    names.insert(name.to_string(), pubkey.to_string());
    let headers = [(header::CACHE_CONTROL, NOSTR_JSON_CACHE_CONTROL)];
    (headers, Json(NostrJsonResponse { names })).into_response()
}

fn not_found() -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(Value::String(String::new())))
}

fn bad_request(message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(Value::String(message.to_string())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::LnurlRepositoryError;
    use crate::repository::{
        AccountIdentifierKind, AccountProvider, NewAccountIdentifier, NewSparkRegistration,
        ResolvedRecipient,
    };
    use crate::routes::test_support::{
        MeMock, MockRepository, Request, Router, ServiceExt, StatusCode, Value,
        internal_route_test_state_full, internal_route_test_state_with_blink_endpoint, json,
        route_test_state_with_country_resolver, start_blink_me_mock_server,
    };
    use nostr::{EventBuilder, Keys, Tag};

    const DOMAIN: &str = "localhost:8080";

    fn proof_event(keys: &Keys, lnaddress: &str, kind: Kind) -> String {
        proof_event_at(keys, &[["lnaddress", lnaddress]], kind, None)
    }

    /// Proof builder with full control: arbitrary tags, and a `created_at`
    /// offset (seconds from now) for freshness tests.
    fn proof_event_at(
        keys: &Keys,
        tags: &[[&str; 2]],
        kind: Kind,
        created_at_offset: Option<i64>,
    ) -> String {
        let created_at = match created_at_offset {
            Some(offset) => now_u64().saturating_add_signed(offset),
            None => now_u64(),
        };
        let parsed: Vec<Tag> = tags
            .iter()
            .map(|t| Tag::parse([t[0], t[1]]).expect("test tag parses"))
            .collect();
        let builder = EventBuilder::new(kind, "")
            .tags(parsed)
            .custom_created_at(created_at.into());
        let event = builder.sign_with_keys(keys).expect("test proof signs");
        event.as_json()
    }

    async fn call(
        app: Router,
        method: &str,
        uri: &str,
        auth: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", DOMAIN);
        if let Some(auth) = auth {
            builder = builder.header("authorization", auth);
        }
        let request = if let Some(body) = body {
            builder
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
        } else {
            builder.body(axum::body::Body::empty())
        }
        .expect("test request builds");
        let response = app.oneshot(request).await.expect("route responds");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body reads");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("response body is JSON")
        };
        (status, body)
    }

    #[test]
    fn valid_local_parts_follow_nip05_charset() {
        assert!(is_valid_nip05_local_part("alice"));
        assert!(is_valid_nip05_local_part("a-b_c.d01"));
        assert!(is_valid_nip05_local_part("_"));
        assert!(!is_valid_nip05_local_part(""));
        assert!(!is_valid_nip05_local_part("Alice"));
        assert!(!is_valid_nip05_local_part("alice@blink.sv"));
        assert!(!is_valid_nip05_local_part("sp ace"));
        assert!(!is_valid_nip05_local_part(&"x".repeat(65)));
    }

    #[test]
    fn nostr_pubkey_normalization_rejects_noncanonical_forms() {
        let hex = "a1b2".repeat(16);
        assert_eq!(normalize_nostr_pubkey(&hex).unwrap(), hex);
        assert_eq!(normalize_nostr_pubkey(&format!(" {hex} ")).unwrap(), hex);
        assert!(normalize_nostr_pubkey(&hex.to_uppercase()).is_err());
        assert!(normalize_nostr_pubkey("npub1something").is_err());
        assert!(normalize_nostr_pubkey(&hex[..63]).is_err());
        assert!(normalize_nostr_pubkey(&format!("{hex}zz")).is_err());
    }

    #[test]
    fn proof_verifier_accepts_valid_authentication_event() {
        let keys = Keys::generate();
        let proof = proof_event(&keys, "alice@localhost:8080", Kind::Authentication);
        assert!(
            verify_nostr_identity_proof(
                &proof,
                &keys.public_key().to_hex(),
                "alice@localhost:8080",
                now_u64()
            )
            .is_ok()
        );
        // The http-auth kind is equally acceptable.
        let proof = proof_event(&keys, "alice@localhost:8080", Kind::HttpAuth);
        assert!(
            verify_nostr_identity_proof(
                &proof,
                &keys.public_key().to_hex(),
                "alice@localhost:8080",
                now_u64()
            )
            .is_ok()
        );
    }

    #[test]
    fn proof_verifier_rejects_wrong_kind_tag_or_key() {
        let keys = Keys::generate();
        let other_keys = Keys::generate();
        let pubkey = keys.public_key().to_hex();

        // Wrong kind.
        let proof = proof_event(&keys, "alice@localhost:8080", Kind::TextNote);
        assert!(
            verify_nostr_identity_proof(&proof, &pubkey, "alice@localhost:8080", now_u64())
                .is_err()
        );

        // Wrong lnaddress binding.
        let proof = proof_event(&keys, "alice@localhost:8080", Kind::Authentication);
        assert!(
            verify_nostr_identity_proof(&proof, &pubkey, "mallory@localhost:8080", now_u64())
                .is_err()
        );

        // Claimed key differs from signing key (impersonation attempt).
        assert!(
            verify_nostr_identity_proof(
                &proof,
                &other_keys.public_key().to_hex(),
                "alice@localhost:8080",
                now_u64()
            )
            .is_err()
        );

        // No lnaddress tag at all.
        let event = EventBuilder::new(Kind::Authentication, "")
            .sign_with_keys(&keys)
            .expect("test event signs");
        assert!(
            verify_nostr_identity_proof(
                &event.as_json(),
                &pubkey,
                "alice@localhost:8080",
                now_u64()
            )
            .is_err()
        );
    }

    fn nostr_json_app(state: State<MockRepository>) -> Router {
        Router::new()
            .route(
                "/.well-known/nostr.json",
                axum::routing::get(LnurlServer::<MockRepository>::handle_nostr_json),
            )
            .layer(Extension(state))
    }

    #[tokio::test]
    async fn nostr_json_serves_overlay_then_registry() {
        let repo =
            MockRepository::default().with_nostr_identity("acct_1", DOMAIN, &"11".repeat(32));
        let mut state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let mut overlay = std::collections::BTreeMap::new();
        overlay.insert("_".to_string(), "22".repeat(32));
        state.nostr_static_names = std::sync::Arc::new(overlay);
        let app = nostr_json_app(state);

        // Overlay wins and is served verbatim.
        let (status, body) = call(
            app.clone(),
            "GET",
            "/.well-known/nostr.json?name=_",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["names"]["_"], "22".repeat(32));
        assert_eq!(
            body["names"].as_object().expect("names is an object").len(),
            1,
            "only the queried name is ever returned"
        );

        // Registry lookup for a registered user.
        let (status, body) = call(
            app.clone(),
            "GET",
            "/.well-known/nostr.json?name=alice",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["names"]["alice"], "11".repeat(32));
    }

    #[tokio::test]
    async fn nostr_json_404s_uniformly_for_unknown_invalid_or_missing_names() {
        let repo = MockRepository::default();
        let state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let app = nostr_json_app(state);

        for uri in [
            "/.well-known/nostr.json?name=nobody",
            "/.well-known/nostr.json?name=Alice",
            "/.well-known/nostr.json?name=alice@blink.sv",
            "/.well-known/nostr.json",
        ] {
            let (status, _) = call(app.clone(), "GET", uri, None, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "uri: {uri}");
        }
    }

    fn spark_registration(pubkey: &str, username: &str) -> NewSparkRegistration {
        NewSparkRegistration {
            account_id: Some(format!("acct_mock_{pubkey}")),
            pubkey: pubkey.to_string(),
            identifier: NewAccountIdentifier {
                domain: DOMAIN.to_string(),
                identifier: username.to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: String::new(),
            },
        }
    }

    #[tokio::test]
    async fn register_nostr_binds_spark_handle_with_dual_proof() {
        let nostr_keys = Keys::generate();
        let nostr_pubkey = nostr_keys.public_key().to_hex();
        // build_auth_payload signs `{username}-{timestamp}`; passing the
        // nostr-prefixed "username" yields exactly the canonical
        // `nostr:{nostr_pubkey}-{timestamp}` message the route validates.
        let timestamp = now_u64();
        let auth =
            spark_client::Client::build_auth_payload(&format!("nostr:{nostr_pubkey}"), timestamp)
                .await
                .expect("test auth payload signs");

        let repo = MockRepository::default().with_spark_mode(&auth.pubkey, None);
        repo.spark_registrations
            .lock()
            .unwrap()
            .push(spark_registration(&auth.pubkey, "alice"));
        let state = route_test_state_with_country_resolver(
            repo.clone(),
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let app = Router::new()
            .route(
                "/lnurlpay/{pubkey}/nostr",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr),
            )
            .layer(Extension(state));

        let (status, body) = call(
            app.clone(),
            "POST",
            &format!("/lnurlpay/{}/nostr", auth.pubkey),
            None,
            Some(json!({
                "nostr_pubkey": nostr_pubkey,
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
                "signature": auth.register_signature,
                "timestamp": timestamp,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["nip05"], "alice@localhost:8080");
        assert_eq!(
            repo.nostr_identity(&format!("acct_mock_{}", auth.pubkey), DOMAIN),
            Some(nostr_pubkey)
        );
    }

    #[tokio::test]
    async fn register_nostr_rejects_bad_signature_and_foreign_proof_key() {
        let nostr_keys = Keys::generate();
        let foreign_keys = Keys::generate();
        let nostr_pubkey = nostr_keys.public_key().to_hex();
        let timestamp = now_u64();
        let auth =
            spark_client::Client::build_auth_payload(&format!("nostr:{nostr_pubkey}"), timestamp)
                .await
                .expect("test auth payload signs");

        let repo = MockRepository::default().with_spark_mode(&auth.pubkey, None);
        repo.spark_registrations
            .lock()
            .unwrap()
            .push(spark_registration(&auth.pubkey, "alice"));
        let state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let app = Router::new()
            .route(
                "/lnurlpay/{pubkey}/nostr",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr),
            )
            .layer(Extension(state));

        // Invalid spark signature.
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/lnurlpay/{}/nostr", auth.pubkey),
            None,
            Some(json!({
                "nostr_pubkey": nostr_pubkey,
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
                "signature": "00".repeat(70),
                "timestamp": timestamp,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Proof signed by a different nostr key than the one claimed.
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/lnurlpay/{}/nostr", auth.pubkey),
            None,
            Some(json!({
                "nostr_pubkey": nostr_pubkey,
                "nostr_proof": proof_event(
                    &foreign_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
                "signature": auth.register_signature,
                "timestamp": timestamp,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    fn blink_recipient(identifier: &str) -> ResolvedRecipient {
        ResolvedRecipient {
            account_id: "acct_blink".to_string(),
            provider: AccountProvider::Blink,
            domain: DOMAIN.to_string(),
            identifier: identifier.to_string(),
            identifier_kind: AccountIdentifierKind::Username,
            description: String::new(),
            spark_pubkey: None,
            blink_account_id: Some("blink-account-1".to_string()),
            btc_wallet_id: None,
            usd_wallet_id: None,
            default_wallet: None,
        }
    }

    #[tokio::test]
    async fn register_nostr_blink_binds_provisioned_username() {
        let endpoint = start_blink_me_mock_server(MeMock::Ok("alice")).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_recipient("alice"));
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));

        let nostr_keys = Keys::generate();
        let nostr_pubkey = nostr_keys.public_key().to_hex();
        let (status, body) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_pubkey,
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["nip05"], "alice@localhost:8080");
        assert_eq!(
            repo.nostr_identity("acct_blink", DOMAIN),
            Some(nostr_pubkey)
        );
    }

    #[test]
    fn proof_verifier_rejects_stale_and_future_proofs() {
        let keys = Keys::generate();
        let pubkey = keys.public_key().to_hex();
        let lnaddress = "alice@localhost:8080";

        let stale = proof_event_at(
            &keys,
            &[["lnaddress", lnaddress]],
            Kind::Authentication,
            Some(-(super::super::ACCEPTABLE_TIME_DIFF_SECS.cast_signed()) * 2),
        );
        assert!(verify_nostr_identity_proof(&stale, &pubkey, lnaddress, now_u64()).is_err());

        let future = proof_event_at(
            &keys,
            &[["lnaddress", lnaddress]],
            Kind::Authentication,
            Some((super::super::ACCEPTABLE_TIME_DIFF_SECS.cast_signed()) * 2),
        );
        assert!(verify_nostr_identity_proof(&future, &pubkey, lnaddress, now_u64()).is_err());

        // Within the window passes.
        let fresh = proof_event_at(
            &keys,
            &[["lnaddress", lnaddress]],
            Kind::Authentication,
            Some(-30),
        );
        assert!(verify_nostr_identity_proof(&fresh, &pubkey, lnaddress, now_u64()).is_ok());
    }

    #[test]
    fn proof_verifier_rejects_duplicate_lnaddress_tags() {
        let keys = Keys::generate();
        let pubkey = keys.public_key().to_hex();
        let lnaddress = "alice@localhost:8080";
        let proof = proof_event_at(
            &keys,
            &[["lnaddress", lnaddress], ["lnaddress", lnaddress]],
            Kind::Authentication,
            None,
        );
        assert!(
            verify_nostr_identity_proof(&proof, &pubkey, lnaddress, now_u64()).is_err(),
            "exactly one lnaddress tag is required"
        );
    }

    #[tokio::test]
    async fn register_nostr_rejects_oversized_proof() {
        let nostr_keys = Keys::generate();
        let nostr_pubkey = nostr_keys.public_key().to_hex();
        let timestamp = now_u64();
        let auth =
            spark_client::Client::build_auth_payload(&format!("nostr:{nostr_pubkey}"), timestamp)
                .await
                .expect("test auth payload signs");
        let repo = MockRepository::default().with_spark_mode(&auth.pubkey, None);
        repo.spark_registrations
            .lock()
            .unwrap()
            .push(spark_registration(&auth.pubkey, "alice"));
        let state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let app = Router::new()
            .route(
                "/lnurlpay/{pubkey}/nostr",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr),
            )
            .layer(Extension(state));

        let (status, body) = call(
            app.clone(),
            "POST",
            &format!("/lnurlpay/{}/nostr", auth.pubkey),
            None,
            Some(json!({
                "nostr_pubkey": nostr_pubkey,
                "nostr_proof": "0".repeat(super::super::MAX_NOSTR_EVENT_SIZE + 1),
                "signature": auth.register_signature,
                "timestamp": timestamp,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    }

    #[tokio::test]
    async fn register_nostr_rejects_unknown_account_or_missing_username() {
        let nostr_keys = Keys::generate();
        let nostr_pubkey = nostr_keys.public_key().to_hex();
        let timestamp = now_u64();
        let auth =
            spark_client::Client::build_auth_payload(&format!("nostr:{nostr_pubkey}"), timestamp)
                .await
                .expect("test auth payload signs");

        // Valid spark signature, but no account exists for the pubkey.
        let repo = MockRepository::default();
        let state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let app = Router::new()
            .route(
                "/lnurlpay/{pubkey}/nostr",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr),
            )
            .layer(Extension(state));
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/lnurlpay/{}/nostr", auth.pubkey),
            None,
            Some(json!({
                "nostr_pubkey": nostr_pubkey,
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
                "signature": auth.register_signature,
                "timestamp": timestamp,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Account exists, but no username on this domain.
        let repo = MockRepository::default().with_spark_mode(&auth.pubkey, None);
        let state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let app = Router::new()
            .route(
                "/lnurlpay/{pubkey}/nostr",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr),
            )
            .layer(Extension(state));
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/lnurlpay/{}/nostr", auth.pubkey),
            None,
            Some(json!({
                "nostr_pubkey": nostr_pubkey,
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
                "signature": auth.register_signature,
                "timestamp": timestamp,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn register_nostr_spark_surfaces_storage_failure() {
        let nostr_keys = Keys::generate();
        let nostr_pubkey = nostr_keys.public_key().to_hex();
        let timestamp = now_u64();
        let auth =
            spark_client::Client::build_auth_payload(&format!("nostr:{nostr_pubkey}"), timestamp)
                .await
                .expect("test auth payload signs");
        let repo = MockRepository::default().with_spark_mode(&auth.pubkey, None);
        repo.spark_registrations
            .lock()
            .unwrap()
            .push(spark_registration(&auth.pubkey, "alice"));
        repo.fail_next_nostr_upsert(LnurlRepositoryError::General(anyhow::anyhow!(
            "disk on fire"
        )));
        let state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let app = Router::new()
            .route(
                "/lnurlpay/{pubkey}/nostr",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr),
            )
            .layer(Extension(state));
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/lnurlpay/{}/nostr", auth.pubkey),
            None,
            Some(json!({
                "nostr_pubkey": nostr_pubkey,
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
                "signature": auth.register_signature,
                "timestamp": timestamp,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn nostr_json_rejects_unapproved_host_even_for_overlay_names() {
        let repo = MockRepository::default();
        let mut state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let mut overlay = std::collections::BTreeMap::new();
        overlay.insert("_".to_string(), "22".repeat(32));
        state.nostr_static_names = std::sync::Arc::new(overlay);
        // Restrict the allowed domains so localhost:8080 is unapproved.
        *state.domains.write().await = std::collections::HashSet::from(["blink.sv".to_string()]);
        let app = nostr_json_app(state);

        let (status, _) = call(
            app.clone(),
            "GET",
            "/.well-known/nostr.json?name=_",
            None,
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "overlay must not bypass Host validation"
        );
    }

    #[tokio::test]
    async fn nostr_json_rate_limits_headerless_requests_in_production_posture() {
        let repo = MockRepository::default();
        let mut state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        // Production posture: tight budget, fail-closed without a trusted header.
        state.nostr_json_rate_limiter =
            std::sync::Arc::new(crate::rate_limit::PerIpRateLimiter::new(
                1,
                std::time::Duration::from_mins(1),
                10,
                false,
            ));
        let app = nostr_json_app(state);

        // Fail-closed posture: without a trusted client-IP header every
        // lookup is refused outright in production (they never even reach
        // the budget — direct-to-origin traffic is not a legitimate path).
        for _ in 0..2 {
            let (status, _) = call(
                app.clone(),
                "GET",
                "/.well-known/nostr.json?name=nobody",
                None,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        }
    }

    #[tokio::test]
    async fn register_nostr_blink_rejects_when_blink_provider_disabled() {
        let endpoint = start_blink_me_mock_server(MeMock::Ok("alice")).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_recipient("alice"));
        let state = internal_route_test_state_full(
            repo,
            None,
            &endpoint,
            true,
            false,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let (status, body) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
        assert_eq!(body, json!("provider_disabled"));
    }

    #[tokio::test]
    async fn register_nostr_blink_rejects_registry_account_mismatch() {
        // `me` authenticates blink-account-1, but the registry entry for
        // `alice` belongs to a different blink account (stale provisioning).
        let endpoint = start_blink_me_mock_server(MeMock::Ok("alice")).await;
        let mut recipient = blink_recipient("alice");
        recipient.blink_account_id = Some("blink-account-OTHER".to_string());
        let repo = MockRepository::default().with_resolved_recipient(recipient);
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn register_nostr_blink_rejects_non_blink_recipient() {
        let endpoint = start_blink_me_mock_server(MeMock::Ok("alice")).await;
        let mut recipient = blink_recipient("alice");
        recipient.provider = AccountProvider::Spark;
        recipient.spark_pubkey = Some("02ab".to_string());
        let repo = MockRepository::default().with_resolved_recipient(recipient);
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn register_nostr_blink_maps_upstream_http_401_to_unauthorized() {
        // A gateway 401 (not a GraphQL-envelope error) must surface as 401,
        // not as a 502 upstream outage (review L3).
        let endpoint = start_blink_me_mock_server(MeMock::HttpUnauthorized).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_recipient("alice"));
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn register_nostr_blink_rejects_lost_ownership_between_proof_and_write() {
        // The username is provisioned to the authenticated account, but the
        // registry ownership check fails at write time (renamed concurrently).
        let endpoint = start_blink_me_mock_server(MeMock::Ok("alice")).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_recipient("alice"));
        repo.fail_next_nostr_upsert(LnurlRepositoryError::InvalidOwnership);
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[test]
    fn proof_verifier_accepts_exact_freshness_boundary() {
        let keys = Keys::generate();
        let pubkey = keys.public_key().to_hex();
        let lnaddress = "alice@localhost:8080";
        let window = super::super::ACCEPTABLE_TIME_DIFF_SECS.cast_signed();

        // Exactly ±window is inside ("too far off" is strict inequality).
        for offset in [-window, window] {
            let proof = proof_event_at(
                &keys,
                &[["lnaddress", lnaddress]],
                Kind::Authentication,
                Some(offset),
            );
            assert!(
                verify_nostr_identity_proof(&proof, &pubkey, lnaddress, now_u64()).is_ok(),
                "offset {offset} sits exactly on the boundary and must pass"
            );
        }
        // One second beyond on either side is stale/future.
        for offset in [-window - 1, window + 1] {
            let proof = proof_event_at(
                &keys,
                &[["lnaddress", lnaddress]],
                Kind::Authentication,
                Some(offset),
            );
            assert!(
                verify_nostr_identity_proof(&proof, &pubkey, lnaddress, now_u64()).is_err(),
                "offset {offset} is beyond the boundary and must fail"
            );
        }
    }

    #[tokio::test]
    async fn nostr_json_maps_lookup_storage_failure_to_500() {
        let repo = MockRepository::default();
        repo.fail_nostr_lookups(LnurlRepositoryError::General(anyhow::anyhow!("db gone")));
        let state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let app = nostr_json_app(state);
        let (status, _) = call(
            app.clone(),
            "GET",
            "/.well-known/nostr.json?name=alice",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn register_nostr_spark_maps_lost_ownership_to_409() {
        let nostr_keys = Keys::generate();
        let nostr_pubkey = nostr_keys.public_key().to_hex();
        let timestamp = now_u64();
        let auth =
            spark_client::Client::build_auth_payload(&format!("nostr:{nostr_pubkey}"), timestamp)
                .await
                .expect("test auth payload signs");
        let repo = MockRepository::default().with_spark_mode(&auth.pubkey, None);
        repo.spark_registrations
            .lock()
            .unwrap()
            .push(spark_registration(&auth.pubkey, "alice"));
        // Ownership of the exact username is lost between proof and write.
        repo.fail_next_nostr_upsert(LnurlRepositoryError::InvalidOwnership);
        let state = route_test_state_with_country_resolver(
            repo,
            crate::country::CountryResolver::disabled(),
        )
        .await;
        let app = Router::new()
            .route(
                "/lnurlpay/{pubkey}/nostr",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr),
            )
            .layer(Extension(state));
        let (status, _) = call(
            app.clone(),
            "POST",
            &format!("/lnurlpay/{}/nostr", auth.pubkey),
            None,
            Some(json!({
                "nostr_pubkey": nostr_pubkey,
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
                "signature": auth.register_signature,
                "timestamp": timestamp,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn register_nostr_blink_maps_upstream_http_403_to_unauthorized() {
        let endpoint = start_blink_me_mock_server(MeMock::HttpForbidden).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_recipient("alice"));
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn register_nostr_blink_maps_null_me_to_unauthorized() {
        let endpoint = start_blink_me_mock_server(MeMock::NullMe).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_recipient("alice"));
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn register_nostr_blink_maps_non_auth_graphql_error_to_502() {
        // An envelope error is not a credential signal (round-2 review):
        // upstream resolver failures are outages, not unauthorized.
        let endpoint = start_blink_me_mock_server(MeMock::GraphqlError).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_recipient("alice"));
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn register_nostr_blink_maps_malformed_200_to_502() {
        // A 200 envelope with no `data` and no errors is a malformed upstream
        // response (round-3 review LOW 2) — an outage, not an auth failure.
        let endpoint = start_blink_me_mock_server(MeMock::Malformed200).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_recipient("alice"));
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn register_nostr_blink_accepts_lowercase_bearer_scheme() {
        // Auth schemes are case-insensitive (round-3 review LOW 3).
        let endpoint = start_blink_me_mock_server(MeMock::Ok("alice")).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_recipient("alice"));
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let nostr_pubkey = nostr_keys.public_key().to_hex();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_pubkey,
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            repo.nostr_identity("acct_blink", DOMAIN),
            Some(nostr_pubkey)
        );
    }

    #[tokio::test]
    async fn register_nostr_blink_rejects_bad_token_and_unprovisioned_username() {
        let endpoint = start_blink_me_mock_server(MeMock::Ok("alice")).await;

        // Valid token, but the username is not provisioned in the registry.
        let repo = MockRepository::default();
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let nostr_keys = Keys::generate();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer good-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Bad token: the mock answers with a GraphQL-envelope error, which is
        // NOT a definitive credential signal under the round-2 contract —
        // that is an upstream-shaped failure (502), not 401.
        let repo = MockRepository::default().with_resolved_recipient(blink_recipient("alice"));
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let app = Router::new()
            .route(
                "/nostr/blink",
                axum::routing::post(LnurlServer::<MockRepository>::register_nostr_blink),
            )
            .layer(Extension(state));
        let (status, _) = call(
            app.clone(),
            "POST",
            "/nostr/blink",
            Some("Bearer wrong-token"),
            Some(json!({
                "nostr_pubkey": nostr_keys.public_key().to_hex(),
                "nostr_proof": proof_event(
                    &nostr_keys,
                    "alice@localhost:8080",
                    Kind::Authentication
                ),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }
}
