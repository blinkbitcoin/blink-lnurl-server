use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::StatusCode,
};
use axum_extra::extract::Host;
use bitcoin::secp256k1::{PublicKey, ecdsa::Signature};
use serde_json::Value;
use tracing::{debug, error, trace, warn};

use crate::{
    identifier::{
        IdentifierError, WalletModifier, canonical_spark_username, parse_public_identifier,
    },
    models::{
        ListMetadataRequest, ListMetadataResponse, RecoverLnurlPayRequest, RecoverLnurlPayResponse,
        RegisterLnurlPayRequest, RegisterLnurlPayResponse, TransferLnurlPayRequest,
        TransferLnurlPayResponse, UnregisterLnurlPayRequest, sanitize_username,
    },
    repository::{
        AccountIdentifierKind, AccountProvider, IdentifierTransfer, LnurlRepository,
        LnurlRepositoryError, NewAccountIdentifier, NewSparkRegistration, ResolvedRecipient,
        WalletKind,
    },
    state::State,
    time::now_u64,
    user::User,
};

use super::{LnurlServer, lnurl_pay::PublicIdentifierIntent, lnurl_pay::PublicRecipient};

impl<DB> LnurlServer<DB>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    pub async fn register(
        Host(host): Host,
        Path(pubkey): Path<String>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<RegisterLnurlPayRequest>,
    ) -> Result<Json<RegisterLnurlPayResponse>, (StatusCode, Json<Value>)> {
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

        let user = state
            .db
            .get_user_by_pubkey(&domain, &pubkey.to_string())
            .await
            .map_err(storage_error)?;

        match user {
            Some(user) => {
                let lnurl = format!("lnurlp://{}/lnurlp/{}", &user.domain, user.name);
                Ok(Json(RecoverLnurlPayResponse {
                    lnurl,
                    lightning_address: format!("{}@{}", user.name, &user.domain),
                    username: user.name,
                    description: user.description,
                }))
            }
            None => Err((
                StatusCode::NOT_FOUND,
                Json(Value::String("user not found".into())),
            )),
        }
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
        | LnurlRepositoryError::InvalidIdentifierKind => {
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

#[allow(dead_code)]
pub(super) fn spark_user_from_recipient(
    recipient: ResolvedRecipient,
) -> Result<User, LnurlRepositoryError> {
    if recipient.provider != AccountProvider::Spark
        || recipient.identifier_kind != AccountIdentifierKind::Username
    {
        return Err(LnurlRepositoryError::InvalidProvider);
    }

    let Some(pubkey) = recipient.spark_pubkey else {
        return Err(LnurlRepositoryError::InvalidOwnership);
    };

    Ok(User {
        domain: recipient.domain,
        pubkey,
        name: recipient.identifier,
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
