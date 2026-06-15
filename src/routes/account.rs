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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invoice_paid::create_provider_invoice_for_account;
    use crate::routes::test_support::*;
    use lightning_invoice::Bolt11Invoice;
    use serde_json::Value;
    use std::str::FromStr;
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

    fn handler_source(name: &str) -> &'static str {
        const SOURCES: [&str; 6] = [
            include_str!("mod.rs"),
            include_str!("account.rs"),
            include_str!("internal.rs"),
            include_str!("lnurl_pay.rs"),
            include_str!("webhook.rs"),
            include_str!("zap.rs"),
        ];

        let marker = format!("    pub async fn {name}(");
        for source in SOURCES {
            if let Some(start) = source.find(&marker) {
                let rest = &source[start..];
                let next = rest.find("\n    pub async fn ").unwrap_or(rest.len());
                return &rest[..next];
            }
        }

        panic!("handler must exist");
    }

    #[test]
    fn spark_management_routes_use_provider_neutral_repository_calls() {
        let register = handler_source("register");
        assert!(
            register.contains("upsert_spark_registration"),
            "register must write through the account-backed Spark registration API"
        );
        assert!(
            !register.contains("upsert_user"),
            "register must not write exclusively through the legacy user API"
        );

        let available = handler_source("available");
        assert!(
            available.contains("resolve_recipient_by_identifier"),
            "availability must resolve account-backed identifiers"
        );
        assert!(
            !available.contains("get_user_by_name"),
            "availability must not rely exclusively on legacy user lookup"
        );

        let recover = handler_source("recover");
        assert!(
            recover.contains("get_account_by_spark_pubkey"),
            "recover must prove Spark account ownership through provider-neutral lookup"
        );

        let unregister = handler_source("unregister");
        assert!(
            unregister.contains("delete_spark_registration"),
            "unregister must delete only the active Spark registration"
        );
        assert!(
            unregister.contains("&username"),
            "unregister must pass the signed canonical username into repository deletion"
        );
        assert!(
            unregister.contains("spark_unregister_error"),
            "unregister must map not-owned targeted deletion to the public not-found convention"
        );
        assert!(
            !unregister.contains("delete_user"),
            "unregister must not delete the legacy user row directly from the route"
        );
    }

    #[test]
    fn transfer_route_uses_provider_neutral_identifier_transfer() {
        let transfer = handler_source("transfer");
        assert!(
            transfer.contains("IdentifierTransfer"),
            "transfer must build the provider-neutral IdentifierTransfer DTO"
        );
        assert!(
            transfer.contains("transfer_identifier"),
            "transfer must move ownership through the provider-neutral repository API"
        );
        assert!(
            transfer.contains("destination_spark_pubkey"),
            "transfer must pass the verified destination Spark pubkey to the repository"
        );
        assert!(
            !transfer.contains("get_account_by_spark_pubkey(&to_pubkey)"),
            "transfer must not require a pre-existing destination Spark account"
        );
        assert!(
            !transfer.contains("transfer_username"),
            "transfer must not rely exclusively on legacy username transfer"
        );
        assert!(
            transfer.contains("verify_transfer_signature"),
            "transfer must preserve both Spark signature checks"
        );
    }

    #[test]
    fn spark_transfer_route_contract_still_uses_provider_neutral_transfer() {
        let transfer = handler_source("transfer");
        assert!(
            transfer.matches("verify_transfer_signature").count() >= 2,
            "public Spark transfer must keep both Spark signature verifications"
        );
        assert!(
            transfer.contains("from_pk == to_pk"),
            "public Spark transfer must keep same source/target pubkey rejection"
        );
        assert!(
            transfer.contains("IdentifierTransfer"),
            "public Spark transfer must still construct IdentifierTransfer"
        );
        assert!(
            transfer.contains("transfer_identifier"),
            "public Spark transfer must still call transfer_identifier"
        );
        assert!(
            transfer.contains("TransferLnurlPayResponse"),
            "public Spark transfer response type must stay unchanged"
        );
        assert!(
            !transfer.contains("SCOPE_TRANSFER_WRITE") && !transfer.contains("require_scope"),
            "public Spark transfer route must not require internal JWT scopes"
        );

        let internal_transfer = handler_source("transfer_identifier_to_spark");
        assert!(
            internal_transfer.contains("SCOPE_TRANSFER_WRITE"),
            "only the internal Blink-to-Spark transfer route should require transfer:write"
        );
        assert!(
            internal_transfer.contains("AccountProvider::Blink"),
            "internal transfer must reject non-Blink current owners"
        );
    }

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

    #[test]
    fn public_invoice_callback_keeps_wallet_aliases_virtual_in_storage_audit() {
        // D-03/PROV-04/LNURL-05: callback identifiers such as alice+btc and
        // alice+usd are public route identities only. Storage and dispatch must
        // use the resolved canonical recipient/account metadata instead.
        let invoice = handler_source("handle_invoice");
        assert!(
            invoice.contains("public_recipient.callback_identifier"),
            "callback metadata hashing should preserve requested public identity"
        );
        assert!(
            invoice.contains("Some(&account_id)")
                && invoice.contains("public_recipient.recipient.provider")
                && invoice.contains("res.wallet_id.as_deref()"),
            "invoice persistence must use resolved account/provider/wallet metadata"
        );
        assert!(
            !invoice.contains("identifier+btc")
                && !invoice.contains("identifier+usd")
                && !invoice.contains("callback_identifier.clone()"),
            "virtual aliases must not be persisted as account identifiers"
        );
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

        let user = spark_user_from_recipient(recipient).expect("Spark recipient should adapt");
        assert_eq!(user.name, "alice");
        assert_eq!(user.domain, "example.com");
        assert_eq!(user.pubkey, "spark_pubkey");
        assert_eq!(user.description, "Alice wallet");
    }

    #[test]
    fn invoice_callback_writes_account_owned_side_effects() {
        let invoice_callback = handler_source("handle_invoice");
        assert!(
            invoice_callback.contains("account_id"),
            "invoice callback must carry resolved account ownership into side effects"
        );
        assert!(
            invoice_callback.contains("create_provider_invoice_for_account"),
            "invoice callback must use provider-aware account invoice construction"
        );
        assert!(
            !invoice_callback.contains("crate::invoice_paid::create_invoice(")
                && !invoice_callback.contains("invoice_paid::create_invoice("),
            "migrated invoice callback must not use the legacy account-less helper"
        );
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
}
