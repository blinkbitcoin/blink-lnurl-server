use axum::{Extension, Json, body::Bytes, extract::Path, http::StatusCode};
use std::collections::HashSet;
use tracing::{error, trace};

use crate::{
    identifier::{IdentifierKind, WalletModifier, parse_public_identifier},
    models::{
        CreateBlinkAccountRequest, CreateBlinkAccountResponse, INTERNAL_ERROR_BLINK_ACCOUNT_EXISTS,
        INTERNAL_ERROR_IDENTIFIER_CONFLICT, INTERNAL_ERROR_INTERNAL_SERVER_ERROR,
        INTERNAL_ERROR_INVALID_DOMAIN, INTERNAL_ERROR_INVALID_IDENTIFIER,
        INTERNAL_ERROR_INVALID_REQUEST, INTERNAL_ERROR_NOT_FOUND,
        INTERNAL_ERROR_WALLET_MODIFIER_NOT_ALLOWED, InternalAccountIdentifierResponse,
        InternalErrorResponse, InternalIdentifierLookupResponse, InternalProviderDetailsResponse,
        InternalTransferToSparkRequest, InternalTransferToSparkResponse,
    },
    repository::{
        AccountIdentifierKind, AccountProvider, BlinkToSparkIdentifierTransfer, LnurlRepository,
        LnurlRepositoryError, NewAccountIdentifier, NewBlinkAccount, ResolvedRecipient, WalletKind,
        generate_account_id,
    },
    state::State,
};

use super::{LnurlServer, account, lnurl_pay};

impl<DB> LnurlServer<DB>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    pub async fn transfer_identifier_to_spark(
        Extension(principal): Extension<crate::internal_auth::InternalPrincipal>,
        Extension(state): Extension<State<DB>>,
        body: Bytes,
    ) -> Result<Json<InternalTransferToSparkResponse>, (StatusCode, Json<InternalErrorResponse>)>
    {
        crate::internal_auth::require_scope(
            &principal,
            crate::internal_auth::SCOPE_TRANSFER_WRITE,
        )?;

        let payload: InternalTransferToSparkRequest =
            serde_json::from_slice(&body).map_err(|e| {
                trace!("invalid internal transfer request JSON: {e}");
                internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST)
            })?;

        let domain = validate_internal_domain(&payload.domain)?;
        let parsed = parse_public_identifier(&payload.identifier).map_err(|e| {
            trace!(
                "invalid internal transfer identifier '{}': {e:?}",
                payload.identifier
            );
            internal_bad_request(INTERNAL_ERROR_INVALID_IDENTIFIER)
        })?;
        if parsed.wallet.is_some() {
            return Err(internal_bad_request(
                INTERNAL_ERROR_WALLET_MODIFIER_NOT_ALLOWED,
            ));
        }
        let identifier = parsed.canonical;
        let destination_spark_pubkey =
            validate_internal_required_string(&payload.destination_spark_pubkey)?;
        let destination_spark_pubkey = account::parse_pubkey(&destination_spark_pubkey)
            .map_err(|_| internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST))?
            .to_string();
        let description = validate_internal_description(&payload.description)?;

        let source_recipient = state
            .db
            .resolve_recipient_by_identifier(&domain, &identifier)
            .await
            .map_err(|e| internal_transfer_to_spark_error(e, &domain, &identifier))?;
        let Some(source_recipient) = source_recipient else {
            return Err(internal_transfer_to_spark_error(
                LnurlRepositoryError::SourceNotOwner,
                &domain,
                &identifier,
            ));
        };
        if source_recipient.provider != AccountProvider::Blink {
            return Err(internal_transfer_to_spark_error(
                LnurlRepositoryError::InvalidOwnership,
                &domain,
                &identifier,
            ));
        }

        state
            .db
            .transfer_blink_identifier_to_spark(&BlinkToSparkIdentifierTransfer {
                domain: domain.clone(),
                identifier: identifier.clone(),
                source_account_id: source_recipient.account_id,
                destination_spark_pubkey: destination_spark_pubkey.clone(),
                description,
            })
            .await
            .map_err(|e| internal_transfer_to_spark_error(e, &domain, &identifier))?;

        Ok(Json(InternalTransferToSparkResponse {
            domain: domain.clone(),
            identifier: identifier.clone(),
            provider: AccountProvider::Spark.as_str().to_string(),
            spark_pubkey: destination_spark_pubkey,
            lightning_address: format!("{identifier}@{domain}"),
            lnurl: format!("lnurlp://{domain}/lnurlp/{identifier}"),
        }))
    }

    pub async fn create_internal_blink_account(
        Extension(principal): Extension<crate::internal_auth::InternalPrincipal>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<CreateBlinkAccountRequest>,
    ) -> Result<Json<CreateBlinkAccountResponse>, (StatusCode, Json<InternalErrorResponse>)> {
        crate::internal_auth::require_scope(
            &principal,
            crate::internal_auth::SCOPE_BLINK_ACCOUNTS_CREATE,
        )?;

        let domain = validate_internal_domain(&payload.domain)?;
        let blink_account_id = validate_internal_required_string(&payload.blink_account_id)?;
        let btc_wallet_id = validate_internal_required_string(&payload.btc_wallet_id)?;
        let usd_wallet_id = validate_internal_required_string(&payload.usd_wallet_id)?;
        let description = validate_internal_description(&payload.description)?;
        if payload.identifiers.is_empty() {
            return Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST));
        }

        let default_wallet = parse_internal_default_wallet(&payload.default_wallet)?;
        let mut identifiers = Vec::with_capacity(payload.identifiers.len());
        let mut response_identifiers = Vec::with_capacity(payload.identifiers.len());
        let mut seen_identifiers = HashSet::with_capacity(payload.identifiers.len());
        for raw_identifier in &payload.identifiers {
            let parsed = parse_public_identifier(raw_identifier).map_err(|e| {
                trace!("invalid internal account identifier '{raw_identifier}': {e:?}");
                internal_bad_request(INTERNAL_ERROR_INVALID_IDENTIFIER)
            })?;
            if parsed.wallet.is_some() {
                return Err(internal_bad_request(
                    INTERNAL_ERROR_WALLET_MODIFIER_NOT_ALLOWED,
                ));
            }
            if !seen_identifiers.insert((domain.clone(), parsed.canonical.clone())) {
                return Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST));
            }
            let identifier_kind = match parsed.kind {
                IdentifierKind::Username => AccountIdentifierKind::Username,
                IdentifierKind::Phone => AccountIdentifierKind::Phone,
            };
            let kind = identifier_kind.as_str().to_string();
            identifiers.push(NewAccountIdentifier {
                domain: domain.clone(),
                identifier: parsed.canonical.clone(),
                identifier_kind,
                description: description.clone(),
            });
            response_identifiers.push(InternalAccountIdentifierResponse {
                identifier: parsed.canonical,
                kind,
                description: description.clone(),
            });
        }

        let account_id = generate_account_id(AccountProvider::Blink);
        let account = NewBlinkAccount {
            account_id: Some(account_id.clone()),
            blink_account_id: blink_account_id.clone(),
            btc_wallet_id: btc_wallet_id.clone(),
            usd_wallet_id: usd_wallet_id.clone(),
            default_wallet,
            identifiers,
        };

        state
            .db
            .create_blink_account(&account)
            .await
            .map_err(internal_account_creation_error)?;

        Ok(Json(CreateBlinkAccountResponse {
            account_id,
            provider: AccountProvider::Blink.as_str().to_string(),
            blink_account_id,
            btc_wallet_id,
            usd_wallet_id,
            default_wallet: default_wallet.as_str().to_string(),
            domain,
            identifiers: response_identifiers,
        }))
    }

    pub async fn get_internal_identifier(
        Extension(principal): Extension<crate::internal_auth::InternalPrincipal>,
        Path((domain, identifier)): Path<(String, String)>,
        Extension(state): Extension<State<DB>>,
    ) -> Result<Json<InternalIdentifierLookupResponse>, (StatusCode, Json<InternalErrorResponse>)>
    {
        crate::internal_auth::require_scope(&principal, crate::internal_auth::SCOPE_ACCOUNTS_READ)?;

        let domain = validate_internal_lookup_domain(&domain)?;
        let parsed = parse_public_identifier(&identifier).map_err(|e| {
            trace!("invalid internal lookup identifier '{identifier}': {e:?}");
            internal_bad_request(INTERNAL_ERROR_INVALID_IDENTIFIER)
        })?;

        let recipient = state
            .db
            .resolve_recipient_by_identifier(&domain, &parsed.canonical)
            .await
            .map_err(|e| internal_lookup_storage_error(&e))?;
        let Some(recipient) = recipient else {
            return Err((
                StatusCode::NOT_FOUND,
                Json(InternalErrorResponse::new(INTERNAL_ERROR_NOT_FOUND)),
            ));
        };

        Ok(Json(internal_identifier_lookup_response(
            recipient,
            parsed.wallet,
        )))
    }
}

fn internal_identifier_lookup_response(
    recipient: ResolvedRecipient,
    requested_wallet: Option<WalletModifier>,
) -> InternalIdentifierLookupResponse {
    InternalIdentifierLookupResponse {
        provider: recipient.provider.as_str().to_string(),
        account_id: recipient.account_id,
        domain: recipient.domain,
        identifier: recipient.identifier,
        identifier_kind: recipient.identifier_kind.as_str().to_string(),
        description: recipient.description,
        requested_wallet: requested_wallet
            .map(|wallet| wallet_modifier_response_value(wallet).to_string()),
        provider_details: InternalProviderDetailsResponse {
            spark_pubkey: recipient.spark_pubkey,
            blink_account_id: recipient.blink_account_id,
            btc_wallet_id: recipient.btc_wallet_id,
            usd_wallet_id: recipient.usd_wallet_id,
            default_wallet: recipient
                .default_wallet
                .map(|wallet| wallet.as_str().to_string()),
        },
    }
}

const fn wallet_modifier_response_value(modifier: WalletModifier) -> &'static str {
    match modifier {
        WalletModifier::Btc => "btc",
        WalletModifier::Usd => "usd",
    }
}

fn validate_internal_domain(
    domain: &str,
) -> Result<String, (StatusCode, Json<InternalErrorResponse>)> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST))
    } else {
        Ok(domain)
    }
}

fn validate_internal_lookup_domain(
    domain: &str,
) -> Result<String, (StatusCode, Json<InternalErrorResponse>)> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() || domain.chars().any(char::is_whitespace) {
        Err(internal_bad_request(INTERNAL_ERROR_INVALID_DOMAIN))
    } else {
        Ok(domain)
    }
}

fn validate_internal_required_string(
    value: &str,
) -> Result<String, (StatusCode, Json<InternalErrorResponse>)> {
    let value = value.trim();
    if value.is_empty() {
        Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST))
    } else {
        Ok(value.to_string())
    }
}

fn validate_internal_description(
    description: &str,
) -> Result<String, (StatusCode, Json<InternalErrorResponse>)> {
    let description = validate_internal_required_string(description)?;
    lnurl_pay::validate_description(&description)
        .map(|()| description)
        .map_err(|(_status, _body)| internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST))
}

fn parse_internal_default_wallet(
    wallet: &str,
) -> Result<WalletKind, (StatusCode, Json<InternalErrorResponse>)> {
    match wallet.trim().to_lowercase().as_str() {
        "btc" => Ok(WalletKind::Btc),
        "usd" => Ok(WalletKind::Usd),
        _ => Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST)),
    }
}

fn internal_account_creation_error(
    error: LnurlRepositoryError,
) -> (StatusCode, Json<InternalErrorResponse>) {
    match error {
        LnurlRepositoryError::BlinkAccountExists => (
            StatusCode::CONFLICT,
            Json(InternalErrorResponse::new(
                INTERNAL_ERROR_BLINK_ACCOUNT_EXISTS,
            )),
        ),
        LnurlRepositoryError::IdentifierConflict | LnurlRepositoryError::NameTaken => (
            StatusCode::CONFLICT,
            Json(InternalErrorResponse::new(
                INTERNAL_ERROR_IDENTIFIER_CONFLICT,
            )),
        ),
        error => {
            error!("failed to create internal Blink account: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(InternalErrorResponse::new(
                    INTERNAL_ERROR_INTERNAL_SERVER_ERROR,
                )),
            )
        }
    }
}

fn internal_transfer_to_spark_error(
    error: LnurlRepositoryError,
    domain: &str,
    identifier: &str,
) -> (StatusCode, Json<InternalErrorResponse>) {
    match error {
        LnurlRepositoryError::SourceNotOwner | LnurlRepositoryError::AccountNotFound => (
            StatusCode::NOT_FOUND,
            Json(InternalErrorResponse::new(INTERNAL_ERROR_NOT_FOUND)),
        ),
        LnurlRepositoryError::InvalidOwnership | LnurlRepositoryError::InvalidProvider => (
            StatusCode::CONFLICT,
            Json(InternalErrorResponse::new(INTERNAL_ERROR_INVALID_REQUEST)),
        ),
        LnurlRepositoryError::IdentifierConflict | LnurlRepositoryError::NameTaken => (
            StatusCode::CONFLICT,
            Json(InternalErrorResponse::new(
                INTERNAL_ERROR_IDENTIFIER_CONFLICT,
            )),
        ),
        error => {
            error!(
                "failed to transfer internal identifier {identifier}@{domain} to Spark: {error}"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(InternalErrorResponse::new(
                    INTERNAL_ERROR_INTERNAL_SERVER_ERROR,
                )),
            )
        }
    }
}

fn internal_lookup_storage_error(
    error: &LnurlRepositoryError,
) -> (StatusCode, Json<InternalErrorResponse>) {
    error!("failed to resolve internal identifier lookup: {error}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(InternalErrorResponse::new(
            INTERNAL_ERROR_INTERNAL_SERVER_ERROR,
        )),
    )
}

fn internal_bad_request(message: &'static str) -> (StatusCode, Json<InternalErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(InternalErrorResponse::new(message)),
    )
}
