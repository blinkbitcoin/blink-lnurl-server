use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
};
use axum_extra::extract::Host;
use bitcoin::secp256k1::{PublicKey, ecdsa::Signature};
use serde_json::Value;
use std::net::IpAddr;
use tracing::{debug, error, trace, warn};

use crate::{
    country::client_ip,
    identifier::{
        IdentifierError, WalletModifier, canonical_spark_username, parse_public_identifier,
    },
    models::{
        ERROR_ENHANCED_MODE_REQUIRED, ERROR_INVALID_MODE, ERROR_MODE_REQUEST_NOT_NEWER,
        ERROR_RATE_LIMITED, ListMetadataRequest, ListMetadataResponse, RecoverLnurlPayRequest,
        RecoverLnurlPayResponse, RegisterLnurlPayRequest, RegisterLnurlPayResponse,
        SetLnurlPayModeRequest, SetLnurlPayModeResponse, TransferLnurlPayRequest,
        TransferLnurlPayResponse, UnregisterLnurlPayRequest, sanitize_username,
    },
    repository::{
        AccountIdentifierKind, AccountMode, AccountProvider, IdentifierTransfer, LnurlRepository,
        LnurlRepositoryError, NewAccountIdentifier, NewSparkRegistration, ResolvedRecipient,
        SparkModeUpdate, WalletKind,
    },
    state::State,
    time::now_u64,
};

use super::{LnurlServer, lnurl_pay::PublicIdentifierIntent, lnurl_pay::PublicRecipient};

const SPARK_PROVIDER_DISABLED_MESSAGE: &str = "Spark provider disabled";

impl<DB> LnurlServer<DB>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    pub async fn register(
        Host(host): Host,
        Path(pubkey): Path<String>,
        Extension(state): Extension<State<DB>>,
        headers: HeaderMap,
        Json(payload): Json<RegisterLnurlPayRequest>,
    ) -> Result<Json<RegisterLnurlPayResponse>, (StatusCode, Json<Value>)> {
        require_spark_provider_enabled(&state)?;

        let username = canonical_spark_username_for_route(&payload.username)?;
        let pubkey = validate(
            &pubkey,
            &payload.signature,
            &username,
            payload.timestamp,
            &state,
        )
        .await?;
        validate_description(&payload.description)?;
        let domain = sanitize_domain(&state, &host).await?;

        let stored_mode = stored_account_mode(&state, &pubkey.to_string()).await?;
        if stored_mode == Some(AccountMode::Anon) {
            return Err(enhanced_mode_required());
        }

        let registration = NewSparkRegistration {
            account_id: None,
            pubkey: pubkey.to_string(),
            identifier: NewAccountIdentifier {
                domain: domain.clone(),
                identifier: username.clone(),
                identifier_kind: AccountIdentifierKind::Username,
                description: payload.description,
            },
        };

        if let Err(e) = state.db.upsert_spark_registration(&registration).await {
            return Err(spark_registration_error(e, &username));
        }

        refresh_country_evidence(&state, &pubkey.to_string(), stored_mode, &headers).await;

        debug!("registered user '{username}' for pubkey {pubkey}");
        let lnurl = format!("lnurlp://{domain}/lnurlp/{username}");
        Ok(Json(RegisterLnurlPayResponse {
            lnurl,
            lightning_address: format!("{username}@{domain}"),
        }))
    }

    pub async fn transfer(
        Host(host): Host,
        Path(to_pubkey): Path<String>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<TransferLnurlPayRequest>,
    ) -> Result<Json<TransferLnurlPayResponse>, (StatusCode, Json<Value>)> {
        require_spark_provider_enabled(&state)?;

        let username = canonical_spark_username_for_route(&payload.username)?;
        validate_description(&payload.description)?;

        let message = format!("transfer:{username}-{to_pubkey}");
        let from_pk = verify_transfer_signature(
            &payload.from_pubkey,
            &payload.from_signature,
            &message,
            &state,
        )
        .await?;
        let to_pk =
            verify_transfer_signature(&to_pubkey, &payload.to_signature, &message, &state).await?;

        if from_pk == to_pk {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(Value::String(
                    "transfer source and target are the same pubkey".into(),
                )),
            ));
        }

        let domain = sanitize_domain(&state, &host).await?;
        let from_pubkey = from_pk.to_string();
        let to_pubkey = to_pk.to_string();

        if stored_account_mode(&state, &to_pubkey).await? == Some(AccountMode::Anon) {
            return Err(enhanced_mode_required());
        }

        let source_recipient = state
            .db
            .resolve_recipient_by_identifier(&domain, &username)
            .await
            .map_err(|e| spark_transfer_error(e, &username))?
            .ok_or_else(|| spark_transfer_error(LnurlRepositoryError::SourceNotOwner, &username))?;

        if source_recipient.spark_pubkey.as_deref() != Some(from_pubkey.as_str()) {
            return Err(spark_transfer_error(
                LnurlRepositoryError::SourceNotOwner,
                &username,
            ));
        }

        if let Err(e) = state
            .db
            .transfer_identifier(&IdentifierTransfer {
                domain: domain.clone(),
                identifier: username.clone(),
                source_account_id: source_recipient.account_id,
                destination_spark_pubkey: to_pubkey.clone(),
                description: payload.description,
            })
            .await
        {
            return Err(spark_transfer_error(e, &username));
        }

        if let Err(e) = state.db.set_spark_mode_enhanced_if_unset(&to_pubkey).await {
            error!("failed to backfill mode after transfer: {e}");
        }

        debug!("transferred '{username}' from {from_pk} to {to_pk}");
        let lnurl = format!("lnurlp://{domain}/lnurlp/{username}");
        Ok(Json(TransferLnurlPayResponse {
            lnurl,
            lightning_address: format!("{username}@{domain}"),
        }))
    }

    pub async fn unregister(
        Host(host): Host,
        Path(pubkey): Path<String>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<UnregisterLnurlPayRequest>,
    ) -> Result<(), (StatusCode, Json<Value>)> {
        require_spark_provider_enabled(&state)?;

        let username = canonical_spark_username_for_route(&payload.username)?;
        let pubkey = validate(
            &pubkey,
            &payload.signature,
            &username,
            payload.timestamp,
            &state,
        )
        .await?;
        let domain = sanitize_domain(&state, &host).await?;

        state
            .db
            .get_account_by_spark_pubkey(&pubkey.to_string())
            .await
            .map_err(storage_error)?;

        state
            .db
            .delete_spark_registration(&domain, &pubkey.to_string(), &username)
            .await
            .map_err(|e| spark_unregister_error(e, &username))?;
        debug!("unregistered user '{username}' for pubkey {pubkey}");
        Ok(())
    }

    pub async fn recover(
        Host(host): Host,
        Path(pubkey): Path<String>,
        Extension(state): Extension<State<DB>>,
        headers: HeaderMap,
        Json(payload): Json<RecoverLnurlPayRequest>,
    ) -> Result<Json<RecoverLnurlPayResponse>, (StatusCode, Json<Value>)> {
        let pubkey = validate(
            &pubkey,
            &payload.signature,
            &pubkey,
            payload.timestamp,
            &state,
        )
        .await?;
        let domain = sanitize_domain(&state, &host).await?;

        let account = state
            .db
            .get_account_by_spark_pubkey(&pubkey.to_string())
            .await
            .map_err(storage_error)?;
        if account.is_none() {
            return Err((
                StatusCode::NOT_FOUND,
                Json(Value::String("user not found".into())),
            ));
        }

        let mode = stored_account_mode(&state, &pubkey.to_string()).await?;
        refresh_country_evidence(&state, &pubkey.to_string(), mode, &headers).await;

        let user = state
            .db
            .get_spark_username_by_pubkey(&domain, &pubkey.to_string())
            .await
            .map_err(storage_error)?;
        let mode = mode.map(|mode| mode.as_str().to_string());

        // An account with a mode but no username is legitimate: mode is recorded
        // before any address can exist.
        match (user, mode.as_ref()) {
            (Some(user), _) => Ok(Json(RecoverLnurlPayResponse {
                lnurl: Some(format!(
                    "lnurlp://{}/lnurlp/{}",
                    &user.domain, user.username
                )),
                lightning_address: Some(format!("{}@{}", user.username, &user.domain)),
                username: Some(user.username),
                description: Some(user.description),
                mode,
            })),
            (None, Some(_)) => Ok(Json(RecoverLnurlPayResponse {
                lnurl: None,
                lightning_address: None,
                username: None,
                description: None,
                mode,
            })),
            (None, None) => Err((
                StatusCode::NOT_FOUND,
                Json(Value::String("user not found".into())),
            )),
        }
    }

    /// `POST /lnurlpay/{pubkey}/mode` — the durable region-determination record.
    /// The pubkey signature is the sole authorization; the client-certificate
    /// middleware in front of this route is transport hygiene, not authz.
    pub async fn set_mode(
        Path(pubkey): Path<String>,
        Extension(state): Extension<State<DB>>,
        headers: HeaderMap,
        Json(payload): Json<SetLnurlPayModeRequest>,
    ) -> Result<Json<SetLnurlPayModeResponse>, (StatusCode, Json<Value>)> {
        require_spark_provider_enabled(&state)?;

        let mode = parse_account_mode(&payload.mode)?;
        let request_ip = client_ip(&headers);
        if !state.ip_rate_limiter.check(request_ip) {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(Value::String(ERROR_RATE_LIMITED.into())),
            ));
        }

        // "mode:" domain-separates from every other signed message; a colon is
        // illegal in usernames, so no register/unregister signature can reach here.
        let message = format!("mode:{}:{}", mode.as_str(), pubkey);
        let pubkey = validate(
            &pubkey,
            &payload.signature,
            &message,
            payload.timestamp,
            &state,
        )
        .await?;
        let client_timestamp = i64::try_from(payload.timestamp).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(Value::String("invalid timestamp".into())),
            )
        })?;

        let country = match mode {
            AccountMode::Enhanced => resolve_country(&state, request_ip).await,
            AccountMode::Anon => None,
        };

        state
            .db
            .upsert_spark_mode(&SparkModeUpdate {
                pubkey: pubkey.to_string(),
                mode,
                client_timestamp,
                country,
            })
            .await
            .map_err(spark_mode_error)?;

        debug!("set mode '{}' for pubkey {pubkey}", mode.as_str());
        Ok(Json(SetLnurlPayModeResponse {
            mode: mode.as_str().to_string(),
        }))
    }

    pub async fn list_metadata(
        Path(pubkey): Path<String>,
        Query(params): Query<ListMetadataRequest>,
        Extension(state): Extension<State<DB>>,
    ) -> Result<Json<ListMetadataResponse>, (StatusCode, Json<Value>)> {
        let pubkey = validate(
            &pubkey,
            &params.signature,
            &pubkey,
            params.timestamp,
            &state,
        )
        .await?;
        let offset = params.offset.unwrap_or(super::DEFAULT_METADATA_OFFSET);
        let limit = params.limit.unwrap_or(super::DEFAULT_METADATA_LIMIT);
        let metadata = state
            .db
            .get_metadata_by_pubkey(&pubkey.to_string(), offset, limit, params.updated_after)
            .await
            .map_err(|e| {
                error!("failed to execute query: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Value::String("internal server error".into())),
                )
            })?;
        Ok(Json(ListMetadataResponse { metadata }))
    }
}

/// Wire parsing is deliberately separate from the storage decoder: a variant
/// added later for storage must not become accepted from untrusted input.
pub(super) fn parse_account_mode(mode: &str) -> Result<AccountMode, (StatusCode, Json<Value>)> {
    match mode.trim() {
        "enhanced" => Ok(AccountMode::Enhanced),
        "anon" => Ok(AccountMode::Anon),
        _ => {
            trace!("invalid mode value");
            Err((
                StatusCode::BAD_REQUEST,
                Json(Value::String(ERROR_INVALID_MODE.into())),
            ))
        }
    }
}

pub(super) fn enhanced_mode_required() -> (StatusCode, Json<Value>) {
    (
        StatusCode::CONFLICT,
        Json(Value::String(ERROR_ENHANCED_MODE_REQUIRED.into())),
    )
}

pub(super) fn spark_mode_error(error: LnurlRepositoryError) -> (StatusCode, Json<Value>) {
    match error {
        LnurlRepositoryError::StaleModeTimestamp => (
            StatusCode::CONFLICT,
            Json(Value::String(ERROR_MODE_REQUEST_NOT_NEWER.into())),
        ),
        error => storage_error(error),
    }
}

pub(super) async fn stored_account_mode<DB>(
    state: &State<DB>,
    pubkey: &str,
) -> Result<Option<AccountMode>, (StatusCode, Json<Value>)>
where
    DB: LnurlRepository + Clone + Send + Sync + 'static,
{
    Ok(state
        .db
        .get_spark_account_mode(pubkey)
        .await
        .map_err(storage_error)?
        .and_then(|record| record.mode))
}

async fn resolve_country<DB>(state: &State<DB>, request_ip: Option<IpAddr>) -> Option<String> {
    state.country_resolver.resolve(request_ip).await
}

/// Refresh the stored country from an accepted end-user signed request. A
/// vendor lookup happens only when the account is already Enhanced — an anon or
/// untyped request never determines a region at all — and only within the same
/// per-IP budget the mode route spends, so routine register/recover traffic
/// cannot drive the paid vendor quota. Over budget, the evidence simply keeps
/// its previous value.
async fn refresh_country_evidence<DB>(
    state: &State<DB>,
    pubkey: &str,
    mode: Option<AccountMode>,
    headers: &HeaderMap,
) where
    DB: LnurlRepository + Clone + Send + Sync + 'static,
{
    if mode != Some(AccountMode::Enhanced) {
        return;
    }
    let request_ip = client_ip(headers);
    if !state.ip_rate_limiter.check(request_ip) {
        debug!("country evidence refresh skipped: per-IP budget spent");
        return;
    }
    let Some(country) = resolve_country(state, request_ip).await else {
        return;
    };
    if let Err(e) = state
        .db
        .refresh_spark_country_evidence(pubkey, &country)
        .await
    {
        error!("failed to refresh country evidence: {e}");
    }
}

pub(super) fn canonical_spark_username_for_route(
    username: &str,
) -> Result<String, (StatusCode, Json<Value>)> {
    canonical_spark_username(username).map_err(|e| {
        trace!("invalid Spark username: {e:?}");
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid username".into())),
        )
    })
}

#[cfg(test)]
pub(super) fn validate_username(username: &str) -> Result<(), (StatusCode, Json<Value>)> {
    canonical_spark_username_for_route(username).map(|_| ())
}

#[cfg(test)]
pub(super) fn public_lookup_username(identifier: &str) -> Result<Option<String>, IdentifierError> {
    let trimmed = identifier.trim();
    if trimmed.is_empty() {
        return Err(IdentifierError::EmptyIdentifier);
    }

    match parse_public_identifier(trimmed) {
        Ok(parsed) => Ok(Some(parsed.canonical)),
        Err(IdentifierError::InvalidUsername) if is_legacy_spark_lookup_candidate(trimmed) => {
            Ok(Some(sanitize_username(trimmed)))
        }
        Err(IdentifierError::InvalidPhoneNumber) if is_phone_like_public_identifier(trimmed) => {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

pub(super) fn parse_public_identifier_for_public_route(
    identifier: &str,
) -> Result<Option<PublicIdentifierIntent>, IdentifierError> {
    let trimmed = identifier.trim();
    if trimmed.is_empty() {
        return Err(IdentifierError::EmptyIdentifier);
    }

    match parse_public_identifier(trimmed) {
        Ok(parsed) => {
            let wallet = parsed.wallet.map(wallet_modifier_to_kind);
            let callback_identifier = match parsed.wallet {
                Some(WalletModifier::Btc) => format!("{}+btc", parsed.canonical),
                Some(WalletModifier::Usd) => format!("{}+usd", parsed.canonical),
                None => parsed.canonical.clone(),
            };
            Ok(Some(PublicIdentifierIntent {
                canonical: parsed.canonical,
                wallet,
                callback_identifier,
            }))
        }
        Err(IdentifierError::InvalidUsername) if is_legacy_spark_lookup_candidate(trimmed) => {
            Ok(Some(PublicIdentifierIntent {
                canonical: sanitize_username(trimmed),
                wallet: None,
                callback_identifier: sanitize_username(trimmed),
            }))
        }
        Err(IdentifierError::InvalidPhoneNumber) if is_phone_like_public_identifier(trimmed) => {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

pub(super) async fn resolve_public_recipient<DB>(
    state: &State<DB>,
    domain: &str,
    intent: PublicIdentifierIntent,
) -> Result<Option<PublicRecipient>, (StatusCode, Json<Value>)>
where
    DB: LnurlRepository + Clone + Send + Sync + 'static,
{
    let recipient = state
        .db
        .resolve_recipient_by_identifier(domain, &intent.canonical)
        .await
        .map_err(|e| {
            error!("failed to execute query: {}", e);
            super::lnurl_pay::lnurl_error("internal server error")
        })?;

    Ok(recipient.map(|recipient| PublicRecipient {
        recipient,
        wallet: intent.wallet,
        callback_identifier: intent.callback_identifier,
    }))
}

const fn wallet_modifier_to_kind(modifier: WalletModifier) -> WalletKind {
    match modifier {
        WalletModifier::Btc => WalletKind::Btc,
        WalletModifier::Usd => WalletKind::Usd,
    }
}

pub(super) fn is_legacy_spark_lookup_candidate(identifier: &str) -> bool {
    !is_phone_like_public_identifier(identifier)
        && !identifier.char_indices().skip(1).any(|(_, ch)| ch == '+')
}

pub(super) fn is_phone_like_public_identifier(identifier: &str) -> bool {
    identifier.starts_with('+')
        || identifier.starts_with("00")
        || identifier.chars().all(|ch| ch.is_ascii_digit())
}

pub(super) fn validate_description(description: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if description.chars().take(256).count() > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Value::String("description too long".into())),
        ));
    }
    Ok(())
}

pub(super) async fn verify_with_spark_client<DB>(
    state: &State<DB>,
    request: spark_client::VerifyMessageRequest<'_>,
) -> Result<(), spark_client::SparkClientError> {
    state.spark_client.verify_message(request).await
}

pub(super) async fn validate<DB>(
    pubkey: &str,
    signature: &str,
    message: &str,
    timestamp: u64,
    state: &State<DB>,
) -> Result<PublicKey, (StatusCode, Json<Value>)> {
    let pubkey = parse_pubkey(pubkey)?;
    let signature = hex::decode(signature).map_err(|e| {
        trace!("invalid signature, could not decode: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid signature".into())),
        )
    })?;
    let signature = Signature::from_der(&signature).map_err(|e| {
        trace!("invalid signature, could not parse: {:?}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid signature".into())),
        )
    })?;

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

    let signed_message = format!("{message}-{timestamp}");
    let verify_request = spark_client::VerifyMessageRequest {
        message: &signed_message,
        signature: &signature,
        public_key: &pubkey,
    };
    verify_with_spark_client(state, verify_request)
        .await
        .map_err(|e| {
            trace!("invalid signature with timestamp, could not verify: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(Value::String("invalid signature".into())),
            )
        })?;

    Ok(pubkey)
}

/// Verify a transfer-route signature over the canonical message
/// `"transfer:{username}-{to_pubkey}"`. Used symmetrically on both ends: the
/// current owner A and the new owner B sign the exact same bytes, and the
/// route calls this once per signature. No timestamp — replay can only
/// re-execute the same A → B → username transfer, which the server-side
/// atomic delete bounds to the case where A still owns the name. The
/// `"transfer:"` prefix domain-separates from `validate()`'s
/// `"{message}-{timestamp}"` format so a captured register signature cannot
/// be replayed as a transfer.
pub(super) async fn verify_transfer_signature<DB>(
    pubkey: &str,
    signature: &str,
    message: &str,
    state: &State<DB>,
) -> Result<PublicKey, (StatusCode, Json<Value>)> {
    let pk = parse_pubkey(pubkey)?;
    let signature = hex::decode(signature).map_err(|e| {
        trace!("invalid transfer signature, could not decode: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid signature".into())),
        )
    })?;
    let signature = Signature::from_der(&signature).map_err(|e| {
        trace!("invalid transfer signature, could not parse: {:?}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid signature".into())),
        )
    })?;

    let verify_request = spark_client::VerifyMessageRequest {
        message,
        signature: &signature,
        public_key: &pk,
    };
    verify_with_spark_client(state, verify_request)
        .await
        .map_err(|e| {
            trace!("invalid transfer signature, could not verify: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(Value::String("invalid signature".into())),
            )
        })?;

    Ok(pk)
}

pub(super) fn parse_pubkey(pubkey: &str) -> Result<PublicKey, (StatusCode, Json<Value>)> {
    let pubkey = hex::decode(pubkey).map_err(|e| {
        trace!("invalid pubkey, could not decode: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid pubkey".into())),
        )
    })?;
    let pubkey = PublicKey::from_slice(&pubkey).map_err(|e| {
        trace!("invalid pubkey, could not parse: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid pubkey".into())),
        )
    })?;
    Ok(pubkey)
}

#[allow(clippy::needless_pass_by_value)]
pub(super) fn storage_error(error: LnurlRepositoryError) -> (StatusCode, Json<Value>) {
    error!("failed to execute query: {error}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(Value::String("internal server error".into())),
    )
}

pub(super) fn spark_transfer_error(
    error: LnurlRepositoryError,
    username: &str,
) -> (StatusCode, Json<Value>) {
    match error {
        LnurlRepositoryError::SourceNotOwner => {
            trace!("transfer source pubkey does not own username '{username}'");
            (
                StatusCode::NOT_FOUND,
                Json(Value::String(
                    "source pubkey does not own this username".into(),
                )),
            )
        }
        LnurlRepositoryError::NameTaken | LnurlRepositoryError::IdentifierConflict => {
            trace!("name already taken during transfer: {username}");
            (
                StatusCode::CONFLICT,
                Json(Value::String("name already taken".into())),
            )
        }
        // Same meaning on every route that can surface it.
        LnurlRepositoryError::StaleModeTimestamp => (
            StatusCode::CONFLICT,
            Json(Value::String(ERROR_MODE_REQUEST_NOT_NEWER.into())),
        ),
        LnurlRepositoryError::General(err) => {
            error!("failed to execute transfer query: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Value::String("internal server error".into())),
            )
        }
        LnurlRepositoryError::BlinkAccountExists
        | LnurlRepositoryError::AccountNotFound
        | LnurlRepositoryError::InvalidOwnership
        | LnurlRepositoryError::InvalidProvider
        | LnurlRepositoryError::InvalidIdentifierKind
        | LnurlRepositoryError::InvalidAccountMode => {
            error!("unexpected provider-neutral transfer error: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Value::String("internal server error".into())),
            )
        }
    }
}

pub(super) fn spark_unregister_error(
    error: LnurlRepositoryError,
    username: &str,
) -> (StatusCode, Json<Value>) {
    match error {
        LnurlRepositoryError::SourceNotOwner => {
            trace!("unregister pubkey does not own username '{username}'");
            (StatusCode::NOT_FOUND, Json(Value::String(String::new())))
        }
        error => storage_error(error),
    }
}

pub(super) fn spark_registration_error(
    error: LnurlRepositoryError,
    username: &str,
) -> (StatusCode, Json<Value>) {
    match error {
        LnurlRepositoryError::NameTaken | LnurlRepositoryError::IdentifierConflict => {
            trace!("name already taken: {username}");
            (
                StatusCode::CONFLICT,
                Json(Value::String("name already taken".into())),
            )
        }
        error => storage_error(error),
    }
}

fn require_spark_provider_enabled<DB>(state: &State<DB>) -> Result<(), (StatusCode, Json<Value>)> {
    if state.providers.spark_enabled() {
        return Ok(());
    }

    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Value::String(SPARK_PROVIDER_DISABLED_MESSAGE.to_string())),
    ))
}

#[allow(dead_code)]
pub(super) fn spark_username_from_recipient(
    recipient: ResolvedRecipient,
) -> Result<crate::repository::SparkUsername, LnurlRepositoryError> {
    if recipient.provider != AccountProvider::Spark
        || recipient.identifier_kind != AccountIdentifierKind::Username
    {
        return Err(LnurlRepositoryError::InvalidProvider);
    }

    let Some(pubkey) = recipient.spark_pubkey else {
        return Err(LnurlRepositoryError::InvalidOwnership);
    };

    Ok(crate::repository::SparkUsername {
        domain: recipient.domain,
        pubkey,
        username: recipient.identifier,
        description: recipient.description,
    })
}

pub(super) async fn sanitize_domain<DB>(
    state: &State<DB>,
    domain: &str,
) -> Result<String, (StatusCode, Json<Value>)> {
    let domain = domain.trim().to_lowercase();
    // If domains list is empty allow all domains (for testing)
    let domains = state.domains.read().await;
    if domains.is_empty() || domains.contains(&domain) {
        return Ok(domain);
    }
    warn!("domain not allowed: {}", domain);
    Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invoice_paid::create_provider_invoice_for_account;
    use crate::routes::test_support::*;
    use lightning_invoice::Bolt11Invoice;
    use serde_json::Value;
    use std::str::FromStr;

    fn assert_spark_provider_disabled(result: Result<impl Sized, (StatusCode, Json<Value>)>) {
        let Err((status, Json(body))) = result else {
            panic!("disabled Spark must reject request");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            Value::String(SPARK_PROVIDER_DISABLED_MESSAGE.to_string())
        );
    }

    fn assert_bad_username(result: Result<(), (StatusCode, Json<Value>)>) {
        let Err((status, Json(body))) = result else {
            panic!("expected invalid username error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, Value::String("invalid username".to_string()));
    }

    #[test]
    fn create_update_username_validation_uses_blink_rules_after_trim() {
        assert!(validate_username(&sanitize_username(" Alice_123 ")).is_ok());

        for invalid in ["", "   ", " alice+foo ", " 12345 ", " bc1alice "] {
            assert_bad_username(validate_username(&sanitize_username(invalid)));
        }
    }

    #[test]
    fn public_lookup_identifier_keeps_legacy_names_but_blocks_phone_like_fallback() {
        assert_eq!(
            public_lookup_username("legacy.name"),
            Ok(Some("legacy.name".to_string()))
        );

        for phone_like in ["12345", "3005871212"] {
            assert_eq!(public_lookup_username(phone_like), Ok(None));
        }
        for phone_like in ["573005871212", "+573005871212", "00573005871212"] {
            assert_eq!(
                public_lookup_username(phone_like),
                Ok(Some("+573005871212".to_string()))
            );
        }
    }

    #[test]
    fn public_lookup_identifier_strips_recognized_modifiers_and_rejects_others() {
        assert_eq!(
            public_lookup_username("alice+BTC"),
            Ok(Some("alice".to_string()))
        );

        for invalid in ["alice+eur", "alice+btc+usd"] {
            assert_eq!(
                public_lookup_username(invalid),
                Err(crate::identifier::IdentifierError::InvalidModifier)
            );
        }
    }

    #[test]
    fn public_identifier_rejects_invalid_wallet_modifier_test_01() {
        let btc = parse_public_identifier_for_public_route("Alice+BTC")
            .expect("BTC modifier should parse")
            .expect("username should produce public intent");
        assert_eq!(btc.canonical, "alice");
        assert_eq!(btc.wallet, Some(WalletKind::Btc));
        assert_eq!(btc.callback_identifier, "alice+btc");

        let usd = parse_public_identifier_for_public_route("alice+Usd")
            .expect("USD modifier should parse")
            .expect("username should produce public intent");
        assert_eq!(usd.canonical, "alice");
        assert_eq!(usd.wallet, Some(WalletKind::Usd));
        assert_eq!(usd.callback_identifier, "alice+usd");

        for invalid in ["alice+eur", "alice+btc+usd", "alice+usd+btc"] {
            assert!(
                matches!(
                    parse_public_identifier_for_public_route(invalid),
                    Err(IdentifierError::InvalidModifier)
                ),
                "invalid wallet modifier must fail before route lookup: {invalid}"
            );
        }
    }

    // -- Spark management account-backed compatibility ------------------------

    #[test]
    fn transfer_provider_neutral_conflicts_keep_legacy_contract() {
        for error in [
            LnurlRepositoryError::NameTaken,
            LnurlRepositoryError::IdentifierConflict,
        ] {
            let (status, Json(body)) = spark_transfer_error(error, "alice");
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body, Value::String("name already taken".to_string()));
        }

        let (status, Json(body)) =
            spark_transfer_error(LnurlRepositoryError::SourceNotOwner, "alice");
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            body,
            Value::String("source pubkey does not own this username".to_string())
        );
    }

    #[test]
    fn metadata_response_preserves_account_id_field() {
        let field_names: Vec<_> = serde_json::to_value(ListMetadataMetadata {
            payment_hash: "metadata_hash".to_string(),
            account_id: Some("acct_spark_metadata".to_string()),
            sender_comment: None,
            nostr_zap_request: None,
            nostr_zap_receipt: None,
            updated_at: 42,
            preimage: None,
        })
        .expect("metadata should serialize")
        .as_object()
        .expect("metadata should serialize as object")
        .keys()
        .cloned()
        .collect();

        assert_eq!(
            field_names,
            vec![
                "account_id",
                "nostr_zap_receipt",
                "nostr_zap_request",
                "payment_hash",
                "preimage",
                "sender_comment",
                "updated_at",
            ]
        );
    }

    #[test]
    fn spark_registration_conflicts_keep_duplicate_name_contract() {
        for error in [
            LnurlRepositoryError::NameTaken,
            LnurlRepositoryError::IdentifierConflict,
        ] {
            let (status, Json(body)) = spark_registration_error(error, "alice");
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body, Value::String("name already taken".to_string()));
        }
    }

    #[tokio::test]
    async fn register_rejects_when_spark_disabled() {
        let state = internal_route_test_state_with_blink_endpoint_and_provider_flags(
            MockRepository::default(),
            None,
            "http://127.0.0.1/graphql",
            false,
            true,
        )
        .await;

        let result = LnurlServer::register(
            Host("example.com".to_string()),
            Path("not-a-pubkey".to_string()),
            Extension(state),
            HeaderMap::new(),
            Json(RegisterLnurlPayRequest {
                username: "alice".to_string(),
                signature: "00".to_string(),
                timestamp: now_u64(),
                description: "Alice".to_string(),
            }),
        )
        .await;

        assert_spark_provider_disabled(result);
    }

    #[tokio::test]
    async fn unregister_rejects_when_spark_disabled() {
        let state = internal_route_test_state_with_blink_endpoint_and_provider_flags(
            MockRepository::default(),
            None,
            "http://127.0.0.1/graphql",
            false,
            true,
        )
        .await;

        let result = LnurlServer::unregister(
            Host("example.com".to_string()),
            Path("not-a-pubkey".to_string()),
            Extension(state),
            Json(UnregisterLnurlPayRequest {
                username: "alice".to_string(),
                signature: "00".to_string(),
                timestamp: now_u64(),
            }),
        )
        .await;

        assert_spark_provider_disabled(result);
    }

    #[tokio::test]
    async fn transfer_rejects_when_spark_disabled() {
        let state = internal_route_test_state_with_blink_endpoint_and_provider_flags(
            MockRepository::default(),
            None,
            "http://127.0.0.1/graphql",
            false,
            true,
        )
        .await;

        let result = LnurlServer::transfer(
            Host("example.com".to_string()),
            Path("not-a-pubkey".to_string()),
            Extension(state),
            Json(TransferLnurlPayRequest {
                username: "alice".to_string(),
                description: "Alice".to_string(),
                from_pubkey: "not-a-pubkey".to_string(),
                from_signature: "00".to_string(),
                to_signature: "00".to_string(),
            }),
        )
        .await;

        assert_spark_provider_disabled(result);
    }

    #[tokio::test]
    async fn post_transfer_public_invoice_uses_spark_provider() {
        let repo =
            MockRepository::default().with_resolved_recipient(post_transfer_spark_recipient());
        let state = internal_route_test_state(repo.clone(), None).await;
        let intent = parse_public_identifier_for_public_route("alice")
            .expect("identifier should parse")
            .expect("username should resolve as public intent");

        let public_recipient = resolve_public_recipient(&state, "example.com", intent)
            .await
            .expect("lookup should not fail")
            .expect("transferred identifier should resolve");
        assert_eq!(public_recipient.recipient.provider, AccountProvider::Spark);
        assert_eq!(
            public_recipient.recipient.spark_pubkey.as_deref(),
            Some("spark_after_transfer_pubkey")
        );

        let (_payment_hash, bolt11) = generate_route_test_invoice(31);
        let invoice = Bolt11Invoice::from_str(&bolt11).expect("test invoice parses");
        let payment_hash = invoice.payment_hash().to_string();
        create_provider_invoice_for_account(
            &repo,
            &payment_hash,
            Some(&public_recipient.recipient.account_id),
            Some(public_recipient.recipient.provider),
            Some(WalletKind::Btc),
            None,
            None,
            public_recipient
                .recipient
                .spark_pubkey
                .as_deref()
                .expect("Spark recipient has pubkey"),
            &bolt11,
            i64::MAX,
            &public_recipient.recipient.domain,
        )
        .await
        .expect("post-transfer Spark invoice should persist");

        let stored = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("new invoice should be persisted");
        assert_eq!(stored.provider, Some(AccountProvider::Spark));
        assert_eq!(stored.wallet_kind, Some(WalletKind::Btc));
        assert_eq!(stored.wallet_id, None);
        assert_eq!(stored.provider_payment_hash, None);
        assert_eq!(
            stored.account_id.as_deref(),
            Some("acct_spark_after_transfer")
        );
        assert_eq!(stored.user_pubkey, "spark_after_transfer_pubkey");
        assert_eq!(stored.domain.as_deref(), Some("example.com"));
    }

    #[tokio::test]
    async fn post_transfer_historical_blink_invoice_owner_is_unchanged() {
        let repo =
            MockRepository::default().with_resolved_recipient(post_transfer_spark_recipient());
        let historical_payment_hash = "historical_blink_before_transfer".to_string();
        repo.upsert_invoice(&Invoice {
            account_id: Some("acct_original_blink".to_string()),
            provider: Some(AccountProvider::Blink),
            wallet_kind: Some(WalletKind::Usd),
            wallet_id: Some("original_blink_usd_wallet".to_string()),
            provider_payment_hash: Some("original_blink_provider_hash".to_string()),
            payment_hash: historical_payment_hash.clone(),
            user_pubkey: String::new(),
            invoice: "lnbc1historicalblink".to_string(),
            preimage: None,
            expired_at: None,
            invoice_expiry: i64::MAX,
            created_at: 1,
            updated_at: 1,
            domain: Some("example.com".to_string()),
            amount_received_sat: Some(42),
        })
        .await
        .unwrap();

        let state = internal_route_test_state(repo.clone(), None).await;
        let intent = parse_public_identifier_for_public_route("alice")
            .expect("identifier should parse")
            .expect("username should resolve as public intent");
        let public_recipient = resolve_public_recipient(&state, "example.com", intent)
            .await
            .expect("lookup should not fail")
            .expect("transferred identifier should resolve");
        assert_eq!(public_recipient.recipient.provider, AccountProvider::Spark);

        let stored = repo
            .get_invoice_by_payment_hash(&historical_payment_hash)
            .await
            .unwrap()
            .expect("historical Blink invoice should remain persisted");
        assert_eq!(stored.provider, Some(AccountProvider::Blink));
        assert_eq!(stored.account_id.as_deref(), Some("acct_original_blink"));
        assert_eq!(stored.wallet_kind, Some(WalletKind::Usd));
        assert_eq!(
            stored.wallet_id.as_deref(),
            Some("original_blink_usd_wallet")
        );
        assert_eq!(stored.payment_hash, historical_payment_hash);
        assert_eq!(stored.amount_received_sat, Some(42));
    }

    #[test]
    fn spark_recipient_adapts_to_legacy_recover_fields() {
        let recipient = crate::repository::ResolvedRecipient {
            account_id: "acct_spark_test".to_string(),
            provider: crate::repository::AccountProvider::Spark,
            domain: "example.com".to_string(),
            identifier: "alice".to_string(),
            identifier_kind: crate::repository::AccountIdentifierKind::Username,
            description: "Alice wallet".to_string(),
            spark_pubkey: Some("spark_pubkey".to_string()),
            blink_account_id: None,
            btc_wallet_id: None,
            usd_wallet_id: None,
            default_wallet: None,
        };

        let user = spark_username_from_recipient(recipient).expect("Spark recipient should adapt");
        assert_eq!(user.username, "alice");
        assert_eq!(user.domain, "example.com");
        assert_eq!(user.pubkey, "spark_pubkey");
        assert_eq!(user.description, "Alice wallet");
    }

    // -- Transfer signature verification ---------------------------------------
    //
    // The transfer route verifies signatures through spark-client. These local
    // checks exercise the same canonical "transfer:{username}-{to_pubkey}"
    // message binding without constructing a runtime Spark client.

    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    /// Deterministic keypair from a seed byte.
    fn transfer_key(seed: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).expect("valid secret key");
        let public = PublicKey::from_secret_key(&secp, &secret);
        (secret, public)
    }

    /// Sign `message` the way the SDK does: ECDSA over `sha256(message)`.
    fn sign(secret: &SecretKey, message: &str) -> Signature {
        let secp = Secp256k1::new();
        let digest = sha256::Hash::hash(message.as_bytes());
        secp.sign_ecdsa(&Message::from_digest(digest.to_byte_array()), secret)
    }

    /// The canonical message the transfer route signs and verifies.
    fn transfer_message(username: &str, to_pubkey: &PublicKey) -> String {
        format!("transfer:{username}-{}", hex::encode(to_pubkey.serialize()))
    }

    #[test]
    fn transfer_signature_accepts_valid() {
        let secp = Secp256k1::new();
        let (alice_secret, alice_pubkey) = transfer_key(1);
        let (_, bob_pubkey) = transfer_key(2);
        let message = transfer_message("alice", &bob_pubkey);
        let sig = sign(&alice_secret, &message);

        assert!(
            secp.verify_ecdsa(
                &Message::from_digest(sha256::Hash::hash(message.as_bytes()).to_byte_array()),
                &sig,
                &alice_pubkey,
            )
            .is_ok(),
            "a valid signature over the canonical message must verify"
        );
    }

    #[test]
    fn transfer_signature_rejects_forged_signer() {
        // Alice signs, but the request attributes the signature to Bob's key.
        let secp = Secp256k1::new();
        let (alice_secret, _) = transfer_key(1);
        let (_, bob_pubkey) = transfer_key(2);
        let message = transfer_message("alice", &bob_pubkey);
        let sig = sign(&alice_secret, &message);

        assert!(
            secp.verify_ecdsa(
                &Message::from_digest(sha256::Hash::hash(message.as_bytes()).to_byte_array()),
                &sig,
                &bob_pubkey,
            )
            .is_err(),
            "a signature made by a different key must be rejected"
        );
    }

    #[test]
    fn transfer_signature_is_bound_to_message() {
        // A signature verifies only for the exact bytes signed: changing the
        // username invalidates it, and a register-style "{name}-{timestamp}"
        // signature cannot be replayed as a transfer (the "transfer:" prefix
        // domain-separates the two flows).
        let secp = Secp256k1::new();
        let (alice_secret, alice_pubkey) = transfer_key(1);
        let (_, bob_pubkey) = transfer_key(2);
        let sig = sign(&alice_secret, &transfer_message("alice", &bob_pubkey));

        let tampered_username = transfer_message("mallory", &bob_pubkey);
        let register_style = String::from("alice-1700000000");
        for other in [tampered_username, register_style] {
            assert!(
                secp.verify_ecdsa(
                    &Message::from_digest(sha256::Hash::hash(other.as_bytes()).to_byte_array()),
                    &sig,
                    &alice_pubkey,
                )
                .is_err(),
                "signature must not verify against a different message: {other}"
            );
        }
    }

    // -- Region-determination mode ---------------------------------------------

    use crate::country::CountryResolver;

    fn mode_key(seed: u8) -> (SecretKey, String) {
        let (secret, public) = transfer_key(seed);
        (secret, hex::encode(public.serialize()))
    }

    fn sign_hex(secret: &SecretKey, message: &str) -> String {
        hex::encode(sign(secret, message).serialize_der())
    }

    fn mode_request(
        secret: &SecretKey,
        pubkey: &str,
        mode: &str,
        timestamp: u64,
    ) -> SetLnurlPayModeRequest {
        SetLnurlPayModeRequest {
            mode: mode.to_string(),
            signature: sign_hex(secret, &format!("mode:{mode}:{pubkey}-{timestamp}")),
            timestamp,
        }
    }

    fn headers_with_request_ip(ip: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", ip.parse().expect("test IP header parses"));
        headers
    }

    async fn post_mode(
        state: &State<MockRepository>,
        pubkey: &str,
        payload: SetLnurlPayModeRequest,
        headers: HeaderMap,
    ) -> Result<SetLnurlPayModeResponse, (StatusCode, Json<Value>)> {
        LnurlServer::set_mode(
            Path(pubkey.to_string()),
            Extension(state.clone()),
            headers,
            Json(payload),
        )
        .await
        .map(|Json(response)| response)
    }

    fn assert_conflict(result: Result<impl Sized, (StatusCode, Json<Value>)>, code: &str) {
        let Err((status, Json(body))) = result else {
            panic!("expected a {code} conflict");
        };
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, Value::String(code.to_string()));
    }

    /// A proxycheck.io stand-in that echoes a fixed isocode and counts lookups.
    async fn start_country_mock(iso_code: &'static str) -> (String, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_route = Arc::clone(&calls);
        let app = Router::new().route(
            "/{ip}",
            get(move |Path(ip): Path<String>| {
                let calls = Arc::clone(&calls_for_route);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Json(json!({ "status": "ok", ip: { "isocode": iso_code, "proxy": "yes", "risk": 100 } }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener should bind");
        let addr = listener
            .local_addr()
            .expect("mock listener should have addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock proxycheck server should serve");
        });
        (format!("http://{addr}"), calls)
    }

    #[tokio::test]
    async fn mode_route_records_a_signed_mode_on_first_contact() {
        let (secret, pubkey) = mode_key(11);
        let repo = MockRepository::default();
        let state =
            route_test_state_with_country_resolver(repo.clone(), CountryResolver::disabled()).await;
        let timestamp = now_u64();

        let response = post_mode(
            &state,
            &pubkey,
            mode_request(&secret, &pubkey, "anon", timestamp),
            HeaderMap::new(),
        )
        .await
        .expect("a validly signed mode request is accepted");

        assert_eq!(response.mode, "anon");
        let record = repo.spark_mode(&pubkey).expect("mode record is created");
        assert_eq!(record.mode, Some(AccountMode::Anon));
        assert_eq!(record.mode_source, Some(ModeSource::Signup));
        assert_eq!(
            record.mode_last_timestamp,
            Some(i64::try_from(timestamp).unwrap())
        );
    }

    #[tokio::test]
    async fn mode_route_rejects_replay_and_captured_older_requests() {
        let (secret, pubkey) = mode_key(12);
        let repo = MockRepository::default();
        let state =
            route_test_state_with_country_resolver(repo.clone(), CountryResolver::disabled()).await;

        // A captured Enhanced request, still well inside the +/-600s window.
        let captured_at = now_u64() - 100;
        let captured = mode_request(&secret, &pubkey, "enhanced", captured_at);
        let _ = post_mode(&state, &pubkey, captured, HeaderMap::new())
            .await
            .expect("the original enhanced request is accepted");

        let switched_at = now_u64();
        let switch = mode_request(&secret, &pubkey, "anon", switched_at);
        let _ = post_mode(
            &state,
            &pubkey,
            SetLnurlPayModeRequest {
                mode: switch.mode.clone(),
                signature: switch.signature.clone(),
                timestamp: switch.timestamp,
            },
            HeaderMap::new(),
        )
        .await
        .expect("the anon switch is accepted");
        let anchored = repo.spark_mode(&pubkey).expect("record exists");

        // Same-signature replay of the accepted anon switch: indistinguishable
        // from the client retrying after a dropped response, so it reads as
        // success — and must change nothing.
        let replayed = post_mode(&state, &pubkey, switch, HeaderMap::new())
            .await
            .expect("a replay of the accepted request is idempotent");
        assert_eq!(replayed.mode, "anon");
        // The rollback case: a *different*, older, still-fresh, validly signed
        // request that would undo the anon consent.
        assert_conflict(
            post_mode(
                &state,
                &pubkey,
                mode_request(&secret, &pubkey, "enhanced", captured_at),
                HeaderMap::new(),
            )
            .await,
            ERROR_MODE_REQUEST_NOT_NEWER,
        );

        assert_eq!(
            repo.spark_mode(&pubkey).expect("record exists"),
            anchored,
            "mode, mode_updated_at and mode_last_timestamp must all be unchanged"
        );
    }

    #[tokio::test]
    async fn mode_route_rejects_a_stale_or_forged_request() {
        let (secret, pubkey) = mode_key(13);
        let (other_secret, _) = mode_key(14);
        let repo = MockRepository::default();
        let state =
            route_test_state_with_country_resolver(repo.clone(), CountryResolver::disabled()).await;

        let stale_timestamp = now_u64() - 601;
        assert!(
            post_mode(
                &state,
                &pubkey,
                mode_request(&secret, &pubkey, "anon", stale_timestamp),
                HeaderMap::new()
            )
            .await
            .is_err(),
            "a request outside the freshness window must be rejected"
        );

        let timestamp = now_u64();
        assert!(
            post_mode(
                &state,
                &pubkey,
                mode_request(&other_secret, &pubkey, "anon", timestamp),
                HeaderMap::new()
            )
            .await
            .is_err(),
            "a signature from another key must be rejected"
        );

        // A signature over "enhanced" must not be replayable as "anon".
        let mut tampered = mode_request(&secret, &pubkey, "enhanced", timestamp);
        tampered.mode = "anon".to_string();
        assert!(
            post_mode(&state, &pubkey, tampered, HeaderMap::new())
                .await
                .is_err(),
            "the signed message binds the mode value"
        );

        let mut bad_mode = mode_request(&secret, &pubkey, "anon", timestamp);
        bad_mode.mode = "hidden".to_string();
        let Err((status, Json(body))) =
            post_mode(&state, &pubkey, bad_mode, HeaderMap::new()).await
        else {
            panic!("an unknown mode value must be rejected");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, Value::String(ERROR_INVALID_MODE.to_string()));

        assert!(repo.spark_mode(&pubkey).is_none());
    }

    #[tokio::test]
    async fn mode_route_resolves_a_country_only_when_storing_enhanced_evidence() {
        let (secret, pubkey) = mode_key(15);
        let (base_url, calls) = start_country_mock("SV").await;
        let repo = MockRepository::default();
        let state = route_test_state_with_country_resolver(
            repo.clone(),
            CountryResolver::new(&base_url, Some("test-key".to_string())).expect("resolver builds"),
        )
        .await;
        let headers = headers_with_request_ip("203.0.113.7");

        let _ = post_mode(
            &state,
            &pubkey,
            mode_request(&secret, &pubkey, "anon", now_u64() - 10),
            headers.clone(),
        )
        .await
        .expect("anon upsert is accepted");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "an anon request must never trigger a vendor lookup"
        );
        assert!(repo.spark_mode(&pubkey).unwrap().country.is_none());

        let _ = post_mode(
            &state,
            &pubkey,
            mode_request(&secret, &pubkey, "enhanced", now_u64()),
            headers.clone(),
        )
        .await
        .expect("enhanced switch is accepted");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let stored = repo.spark_mode(&pubkey).unwrap();
        assert_eq!(stored.country.as_deref(), Some("SV"));

        let _ = post_mode(
            &state,
            &pubkey,
            mode_request(&secret, &pubkey, "anon", now_u64() + 1),
            headers,
        )
        .await
        .expect("anon switch back is accepted");
        let cleared = repo.spark_mode(&pubkey).unwrap();
        assert_eq!(cleared.mode, Some(AccountMode::Anon));
        assert!(cleared.country.is_none());
        assert!(cleared.country_updated_at.is_none());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "switching away from enhanced must not resolve anything"
        );
    }

    #[tokio::test]
    async fn mode_route_ignores_untrusted_ip_headers() {
        let (secret, pubkey) = mode_key(16);
        let (base_url, calls) = start_country_mock("SV").await;
        let repo = MockRepository::default();
        let state = route_test_state_with_country_resolver(
            repo.clone(),
            CountryResolver::new(&base_url, None).expect("resolver builds"),
        )
        .await;

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let _ = post_mode(
            &state,
            &pubkey,
            mode_request(&secret, &pubkey, "enhanced", now_u64()),
            headers,
        )
        .await
        .expect("enhanced upsert is accepted");

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            repo.spark_mode(&pubkey).unwrap().country.is_none(),
            "only x-real-ip may feed the evidence store"
        );
    }

    #[tokio::test]
    async fn mode_route_is_rate_limited_per_ip() {
        let (secret, pubkey) = mode_key(17);
        let repo = MockRepository::default();
        let mut state =
            route_test_state_with_country_resolver(repo.clone(), CountryResolver::disabled()).await;
        state.ip_rate_limiter = Arc::new(crate::rate_limit::PerIpRateLimiter::new(
            1,
            std::time::Duration::from_mins(1),
            16,
            false,
        ));
        let headers = headers_with_request_ip("203.0.113.7");

        let _ = post_mode(
            &state,
            &pubkey,
            mode_request(&secret, &pubkey, "anon", now_u64()),
            headers.clone(),
        )
        .await
        .expect("the first request is within budget");

        let Err((status, Json(body))) = post_mode(
            &state,
            &pubkey,
            mode_request(&secret, &pubkey, "enhanced", now_u64() + 1),
            headers,
        )
        .await
        else {
            panic!("the second request must be throttled");
        };
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, Value::String(ERROR_RATE_LIMITED.to_string()));

        // No trusted header means no budget outside a local deployment: the
        // signature-verification RPC must not be reachable without one.
        let Err((status, _)) = post_mode(
            &state,
            &pubkey,
            mode_request(&secret, &pubkey, "anon", now_u64() + 2),
            HeaderMap::new(),
        )
        .await
        else {
            panic!("a request with no trusted client IP must be throttled");
        };
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_fast_client_clock_does_not_wedge_later_mode_requests() {
        // The device is 5 minutes fast but still inside the freshness window;
        // the account must stay usable from a correctly clocked one.
        let (secret, pubkey) = mode_key(26);
        let repo = MockRepository::default();
        let state =
            route_test_state_with_country_resolver(repo.clone(), CountryResolver::disabled()).await;
        let now = now_u64();

        let _ = post_mode(
            &state,
            &pubkey,
            mode_request(&secret, &pubkey, "anon", now + 300),
            HeaderMap::new(),
        )
        .await
        .expect("a request from a fast clock is still validly signed and fresh");
        let anchor = repo
            .spark_mode(&pubkey)
            .unwrap()
            .mode_last_timestamp
            .expect("an accepted request always anchors");
        assert!(
            anchor <= i64::try_from(now_u64()).unwrap()
                && anchor < i64::try_from(now + 300).unwrap(),
            "the stored anchor must be clamped to server time"
        );

        let _ = post_mode(
            &state,
            &pubkey,
            mode_request(
                &secret,
                &pubkey,
                "enhanced",
                u64::try_from(anchor).unwrap() + 1,
            ),
            HeaderMap::new(),
        )
        .await
        .expect("the user's correctly clocked device must not be locked out");
        assert_eq!(
            repo.spark_mode(&pubkey).unwrap().mode,
            Some(AccountMode::Enhanced)
        );

        // Rollback protection is unchanged.
        assert_conflict(
            post_mode(
                &state,
                &pubkey,
                mode_request(&secret, &pubkey, "anon", now - 60),
                HeaderMap::new(),
            )
            .await,
            ERROR_MODE_REQUEST_NOT_NEWER,
        );
    }

    #[tokio::test]
    async fn an_identical_mode_request_retried_after_a_dropped_response_succeeds() {
        let (secret, pubkey) = mode_key(27);
        let repo = MockRepository::default();
        let state =
            route_test_state_with_country_resolver(repo.clone(), CountryResolver::disabled()).await;
        let timestamp = now_u64();
        let request = mode_request(&secret, &pubkey, "anon", timestamp);

        let _ = post_mode(
            &state,
            &pubkey,
            mode_request(&secret, &pubkey, "anon", timestamp),
            HeaderMap::new(),
        )
        .await
        .expect("the first attempt is accepted");
        let accepted = repo.spark_mode(&pubkey).unwrap();

        let response = post_mode(&state, &pubkey, request, HeaderMap::new())
            .await
            .expect("the retry of a request that did land must read as success");
        assert_eq!(response.mode, "anon");
        assert_eq!(repo.spark_mode(&pubkey).unwrap(), accepted);

        // A captured request at the same timestamp but another mode is not a
        // retry, and is still refused.
        assert_conflict(
            post_mode(
                &state,
                &pubkey,
                mode_request(&secret, &pubkey, "enhanced", timestamp),
                HeaderMap::new(),
            )
            .await,
            ERROR_MODE_REQUEST_NOT_NEWER,
        );
    }

    #[tokio::test]
    async fn the_country_refresh_path_spends_the_same_per_ip_budget() {
        // Recover is a routine app-restore call: it must not be able to drive
        // the paid vendor quota beyond the per-IP budget.
        let (secret, pubkey) = mode_key(28);
        let (base_url, calls) = start_country_mock("SV").await;
        let repo = MockRepository::default().with_spark_mode(&pubkey, Some(AccountMode::Enhanced));
        let mut state = route_test_state_with_country_resolver(
            repo.clone(),
            CountryResolver::new(&base_url, None).expect("resolver builds"),
        )
        .await;
        state.ip_rate_limiter = Arc::new(crate::rate_limit::PerIpRateLimiter::new(
            1,
            std::time::Duration::from_mins(1),
            16,
            false,
        ));
        let headers = headers_with_request_ip("203.0.113.7");

        for attempt in 0..3 {
            let timestamp = now_u64() + attempt;
            let _ = LnurlServer::recover(
                Host("example.com".to_string()),
                Path(pubkey.clone()),
                Extension(state.clone()),
                headers.clone(),
                Json(RecoverLnurlPayRequest {
                    signature: sign_hex(&secret, &format!("{pubkey}-{timestamp}")),
                    timestamp,
                }),
            )
            .await
            .expect("recover keeps working while over budget");
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only the in-budget recover may reach the vendor"
        );
    }

    #[test]
    fn wire_mode_values_are_parsed_independently_of_the_storage_decoder() {
        assert_eq!(
            parse_account_mode(" enhanced ").ok(),
            Some(AccountMode::Enhanced)
        );
        assert_eq!(parse_account_mode("anon").ok(), Some(AccountMode::Anon));

        for invalid in ["", "ENHANCED", "hidden", "signup", "ip", "null"] {
            let Err((status, Json(body))) = parse_account_mode(invalid) else {
                panic!("wire value '{invalid}' must be rejected");
            };
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body, Value::String(ERROR_INVALID_MODE.to_string()));
        }
    }

    #[test]
    fn a_stale_mode_timestamp_is_a_conflict_on_every_route() {
        let (status, Json(body)) =
            spark_transfer_error(LnurlRepositoryError::StaleModeTimestamp, "alice");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body,
            Value::String(ERROR_MODE_REQUEST_NOT_NEWER.to_string())
        );

        let (mode_status, Json(mode_body)) =
            spark_mode_error(LnurlRepositoryError::StaleModeTimestamp);
        assert_eq!(mode_status, status);
        assert_eq!(mode_body, body);
    }

    #[tokio::test]
    async fn register_is_refused_while_anon_and_allowed_while_untyped() {
        let (secret, pubkey) = mode_key(18);
        let repo = MockRepository::default().with_spark_mode(&pubkey, Some(AccountMode::Anon));
        let state =
            route_test_state_with_country_resolver(repo.clone(), CountryResolver::disabled()).await;
        let timestamp = now_u64();

        let request = RegisterLnurlPayRequest {
            username: "alice".to_string(),
            signature: sign_hex(&secret, &format!("alice-{timestamp}")),
            timestamp,
            description: "Alice".to_string(),
        };
        assert_conflict(
            LnurlServer::register(
                Host("example.com".to_string()),
                Path(pubkey.clone()),
                Extension(state.clone()),
                HeaderMap::new(),
                Json(request),
            )
            .await,
            ERROR_ENHANCED_MODE_REQUIRED,
        );
        assert_eq!(repo.spark_registration_count(), 0);

        let untyped_repo = MockRepository::default();
        let untyped_state = route_test_state_with_country_resolver(
            untyped_repo.clone(),
            CountryResolver::disabled(),
        )
        .await;
        let _ = LnurlServer::register(
            Host("example.com".to_string()),
            Path(pubkey.clone()),
            Extension(untyped_state),
            HeaderMap::new(),
            Json(RegisterLnurlPayRequest {
                username: "alice".to_string(),
                signature: sign_hex(&secret, &format!("alice-{timestamp}")),
                timestamp,
                description: "Alice".to_string(),
            }),
        )
        .await
        .expect("an untyped account keeps its grandfathered registration");
        assert_eq!(untyped_repo.spark_registration_count(), 1);
        assert!(
            untyped_repo.spark_mode(&pubkey).is_none(),
            "register must not type an account"
        );
    }

    #[tokio::test]
    async fn register_refreshes_country_evidence_only_while_enhanced() {
        let (secret, pubkey) = mode_key(19);
        let (base_url, calls) = start_country_mock("CO").await;
        let repo = MockRepository::default().with_spark_mode(&pubkey, Some(AccountMode::Enhanced));
        let state = route_test_state_with_country_resolver(
            repo.clone(),
            CountryResolver::new(&base_url, None).expect("resolver builds"),
        )
        .await;
        let timestamp = now_u64();

        let _ = LnurlServer::register(
            Host("example.com".to_string()),
            Path(pubkey.clone()),
            Extension(state),
            headers_with_request_ip("203.0.113.7"),
            Json(RegisterLnurlPayRequest {
                username: "alice".to_string(),
                signature: sign_hex(&secret, &format!("alice-{timestamp}")),
                timestamp,
                description: "Alice".to_string(),
            }),
        )
        .await
        .expect("an enhanced account may claim a username");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            repo.spark_mode(&pubkey).unwrap().country.as_deref(),
            Some("CO")
        );
    }

    #[tokio::test]
    async fn register_and_recover_never_resolve_for_anon_or_untyped_accounts() {
        for mode in [Some(AccountMode::Anon), None] {
            let (secret, pubkey) = mode_key(22);
            let (base_url, calls) = start_country_mock("CO").await;
            let repo = MockRepository::default().with_spark_mode(&pubkey, mode);
            let state = route_test_state_with_country_resolver(
                repo.clone(),
                CountryResolver::new(&base_url, None).expect("resolver builds"),
            )
            .await;
            let timestamp = now_u64();

            let recovered = LnurlServer::recover(
                Host("example.com".to_string()),
                Path(pubkey.clone()),
                Extension(state.clone()),
                headers_with_request_ip("203.0.113.7"),
                Json(RecoverLnurlPayRequest {
                    signature: sign_hex(&secret, &format!("{pubkey}-{timestamp}")),
                    timestamp,
                }),
            )
            .await;
            match mode {
                Some(_) => {
                    let _ = recovered.expect("an anon account recovers its mode");
                }
                // No username and no mode leaves nothing to recover; the 404
                // must still happen after the (skipped) evidence refresh.
                None => assert!(recovered.is_err()),
            }

            let _ = LnurlServer::register(
                Host("example.com".to_string()),
                Path(pubkey.clone()),
                Extension(state),
                headers_with_request_ip("203.0.113.7"),
                Json(RegisterLnurlPayRequest {
                    username: "alice".to_string(),
                    signature: sign_hex(&secret, &format!("alice-{timestamp}")),
                    timestamp,
                    description: "Alice".to_string(),
                }),
            )
            .await;

            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "a non-enhanced account's ip must never reach the vendor (mode: {mode:?})"
            );
            assert!(
                repo.spark_mode(&pubkey)
                    .is_none_or(|record| record.country.is_none()),
                "no country evidence may appear for mode: {mode:?}"
            );
        }
    }

    #[tokio::test]
    async fn recover_returns_the_mode_and_tolerates_address_less_accounts() {
        let (secret, pubkey) = mode_key(20);
        let repo = MockRepository::default().with_spark_mode(&pubkey, Some(AccountMode::Anon));
        let state =
            route_test_state_with_country_resolver(repo.clone(), CountryResolver::disabled()).await;
        let timestamp = now_u64();

        let Json(response) = LnurlServer::recover(
            Host("example.com".to_string()),
            Path(pubkey.clone()),
            Extension(state),
            HeaderMap::new(),
            Json(RecoverLnurlPayRequest {
                signature: sign_hex(&secret, &format!("{pubkey}-{timestamp}")),
                timestamp,
            }),
        )
        .await
        .expect("a mode-only account must recover");

        assert_eq!(response.mode.as_deref(), Some("anon"));
        assert!(response.username.is_none());
        assert!(response.lightning_address.is_none());
        let body = serde_json::to_value(&response).expect("response serializes");
        assert_eq!(
            body.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec!["mode"],
            "address fields stay absent rather than null for a mode-only account"
        );
    }

    #[tokio::test]
    async fn recover_404s_for_a_pubkey_with_no_record() {
        let (secret, pubkey) = mode_key(21);
        let state = route_test_state_with_country_resolver(
            MockRepository::default(),
            CountryResolver::disabled(),
        )
        .await;
        let timestamp = now_u64();

        let Err((status, _)) = LnurlServer::recover(
            Host("example.com".to_string()),
            Path(pubkey.clone()),
            Extension(state),
            HeaderMap::new(),
            Json(RecoverLnurlPayRequest {
                signature: sign_hex(&secret, &format!("{pubkey}-{timestamp}")),
                timestamp,
            }),
        )
        .await
        else {
            panic!("an unknown pubkey must still 404");
        };
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    async fn run_user_transfer(
        repo: MockRepository,
        from: &SecretKey,
        from_pubkey: &str,
        to: &SecretKey,
        to_pubkey: &str,
    ) -> Result<Json<TransferLnurlPayResponse>, (StatusCode, Json<Value>)> {
        let state = route_test_state_with_country_resolver(repo, CountryResolver::disabled()).await;
        let message = format!("transfer:alice-{to_pubkey}");
        LnurlServer::transfer(
            Host("example.com".to_string()),
            Path(to_pubkey.to_string()),
            Extension(state),
            Json(TransferLnurlPayRequest {
                username: "alice".to_string(),
                description: "Alice".to_string(),
                from_pubkey: from_pubkey.to_string(),
                from_signature: sign_hex(from, &message),
                to_signature: sign_hex(to, &message),
            }),
        )
        .await
    }

    fn transfer_source_recipient(from_pubkey: &str) -> ResolvedRecipient {
        ResolvedRecipient {
            spark_pubkey: Some(from_pubkey.to_string()),
            ..spark_resolved_recipient()
        }
    }

    #[tokio::test]
    async fn user_transfer_is_refused_when_the_destination_is_anon() {
        let (from, from_pubkey) = mode_key(22);
        let (to, to_pubkey) = mode_key(23);
        let repo = MockRepository::default()
            .with_resolved_recipient(transfer_source_recipient(&from_pubkey))
            .with_spark_mode(&to_pubkey, Some(AccountMode::Anon));

        assert_conflict(
            run_user_transfer(repo.clone(), &from, &from_pubkey, &to, &to_pubkey).await,
            ERROR_ENHANCED_MODE_REQUIRED,
        );
    }

    #[tokio::test]
    async fn user_transfer_backfills_an_unset_destination_mode() {
        let (from, from_pubkey) = mode_key(24);
        let (to, to_pubkey) = mode_key(25);
        let repo = MockRepository::default()
            .with_resolved_recipient(transfer_source_recipient(&from_pubkey));

        let _ = run_user_transfer(repo.clone(), &from, &from_pubkey, &to, &to_pubkey)
            .await
            .expect("an untyped destination may receive the identifier");

        let record = repo.spark_mode(&to_pubkey).expect("mode record is created");
        assert_eq!(record.mode, Some(AccountMode::Enhanced));
        assert_eq!(record.mode_source, Some(ModeSource::Migration));
        assert!(record.country.is_none());
    }
}
