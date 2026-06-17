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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_support::*;
    use serde_json::{Value, json};
    #[tokio::test]
    async fn create_internal_blink_account_happy_path_requires_valid_internal_token() {
        // D-01/D-04/D-08/D-09/D-13/D-14/D-16/D-17/D-19: the internal account
        // creation happy path is locked to /internal/blink/accounts, a scoped
        // RS256 JWT, local deterministic JWKS/key fixtures, route-boundary
        // normalization, and exactly one provider-neutral repository write.
        let jwks = include_str!("../../tests/fixtures/internal_auth_jwks.json");
        let private_key = include_bytes!("../../tests/fixtures/internal_auth_private.pem");
        let auth_state = Arc::new(
            crate::internal_auth::InternalAuthState::from_jwks_json(
                jwks,
                "https://issuer.internal.test".to_string(),
                "lnurl-server.internal.test".to_string(),
            )
            .expect("test JWKS fixture must load"),
        );

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("blink-internal-test-key".to_string());
        let token = encode(
            &header,
            &serde_json::json!({
                "sub": "blink-core-test-service",
                "iss": "https://issuer.internal.test",
                "aud": "lnurl-server.internal.test",
                "exp": 4_102_444_800_u64,
                "nbf": 1_700_000_000_u64,
                "scope": "blink:accounts:create accounts:read"
            }),
            &EncodingKey::from_rsa_pem(private_key).expect("test RSA key must parse"),
        )
        .expect("test JWT must sign");

        let repo = MockRepository::default();
        let state = internal_route_test_state(repo.clone(), Some(auth_state)).await;
        let app = Router::new()
            .route(
                "/internal/blink/accounts",
                post(LnurlServer::<MockRepository>::create_internal_blink_account),
            )
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                crate::internal_auth::internal_auth::<MockRepository>,
            ))
            .layer(Extension(state));

        let request = Request::builder()
            .method("POST")
            .uri("/internal/blink/accounts")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&CreateBlinkAccountRequest {
                    domain: "Example.COM".to_string(),
                    blink_account_id: "blink_account_123".to_string(),
                    btc_wallet_id: "btc_wallet_123".to_string(),
                    usd_wallet_id: "usd_wallet_123".to_string(),
                    default_wallet: "usd".to_string(),
                    description: "Blink account".to_string(),
                    identifiers: vec![" Alice_123 ".to_string(), "+573005871212".to_string()],
                })
                .expect("request serializes"),
            ))
            .expect("request builds");

        let response = app.oneshot(request).await.expect("route responds");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body reads");
        let response: CreateBlinkAccountResponse =
            serde_json::from_slice(&body).expect("response deserializes");
        assert_eq!(response.provider, "blink");
        assert_eq!(response.domain, "example.com");
        assert_eq!(response.identifiers[0].identifier, "alice_123");

        let created = repo.created_blink_accounts.lock().unwrap();
        assert_eq!(
            created.len(),
            1,
            "create_blink_account is called exactly once"
        );
        let account = &created[0];
        assert!(
            account
                .account_id
                .as_deref()
                .is_some_and(|id| id.starts_with("acct_blink_"))
        );
        assert_eq!(account.blink_account_id, "blink_account_123");
        assert_eq!(account.default_wallet, WalletKind::Usd);
        assert_eq!(account.identifiers.len(), 2);
        assert_eq!(account.identifiers[0].domain, "example.com");
        assert_eq!(account.identifiers[0].identifier, "alice_123");
        assert_eq!(
            account.identifiers[0].identifier_kind,
            AccountIdentifierKind::Username
        );
        assert_eq!(account.identifiers[0].description, "Blink account");
        assert_eq!(account.identifiers[1].identifier, "+573005871212");
        assert_eq!(
            account.identifiers[1].identifier_kind,
            AccountIdentifierKind::Phone
        );
    }

    #[tokio::test]
    async fn internal_blink_account_validation_rejects_missing_identifiers_without_repository_write()
     {
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let mut payload = valid_create_blink_account_payload();
        payload.identifiers.clear();

        let (status, body) = post_internal_blink_account(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_request"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_validation_rejects_invalid_default_wallet_without_repository_write()
     {
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let mut payload = valid_create_blink_account_payload();
        payload.default_wallet = "eur".to_string();

        let (status, body) = post_internal_blink_account(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_request"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_validation_rejects_invalid_identifier_without_repository_write()
    {
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let mut payload = valid_create_blink_account_payload();
        payload.identifiers = vec!["not valid".to_string()];

        let (status, body) = post_internal_blink_account(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_identifier"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_validation_rejects_wallet_modifier_without_repository_write() {
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let mut payload = valid_create_blink_account_payload();
        payload.identifiers = vec!["alice+btc".to_string()];

        let (status, body) = post_internal_blink_account(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "wallet_modifier_not_allowed"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_validation_rejects_duplicate_normalized_identifier_without_repository_write()
     {
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let mut payload = valid_create_blink_account_payload();
        payload.identifiers = vec!["Alice_123".to_string(), " alice_123 ".to_string()];

        let (status, body) = post_internal_blink_account(app, payload).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "invalid_request"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_conflict_maps_duplicate_blink_account_to_409() {
        let repo = MockRepository::default();
        repo.fail_next_blink_account_creation(MockCreateBlinkAccountError::BlinkAccountExists);
        let app = internal_account_app(repo.clone()).await;

        let (status, body) =
            post_internal_blink_account(app, valid_create_blink_account_payload()).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "blink_account_exists"}));
        assert_eq!(repo.created_blink_account_count(), 1);
    }

    #[tokio::test]
    async fn internal_blink_account_conflict_maps_identifier_conflict_to_409() {
        let repo = MockRepository::default();
        repo.fail_next_blink_account_creation(MockCreateBlinkAccountError::IdentifierConflict);
        let app = internal_account_app(repo.clone()).await;

        let (status, body) =
            post_internal_blink_account(app, valid_create_blink_account_payload()).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "identifier_conflict"}));
        assert_eq!(repo.created_blink_account_count(), 1);
    }

    #[tokio::test]
    async fn internal_blink_account_conflict_maps_name_taken_fallback_to_409() {
        let repo = MockRepository::default();
        repo.fail_next_blink_account_creation(MockCreateBlinkAccountError::NameTaken);
        let app = internal_account_app(repo.clone()).await;

        let (status, body) =
            post_internal_blink_account(app, valid_create_blink_account_payload()).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "identifier_conflict"}));
        assert_eq!(repo.created_blink_account_count(), 1);
    }

    #[tokio::test]
    async fn internal_blink_account_fails_closed_when_internal_auth_config_is_absent() {
        // D-03/D-07/D-27: absent configured internal auth state returns 401 before handler writes.
        let repo = MockRepository::default();
        let state = internal_route_test_state(repo.clone(), None).await;
        let app = internal_account_app_with_state(state);

        let (status, body) =
            post_internal_blink_account(app, valid_create_blink_account_payload()).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, Value::Null);
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_blink_account_requires_create_scope_before_repository_write() {
        // D-09/D-10: valid internal JWTs without the route scope receive 403.
        let repo = MockRepository::default();
        let app = internal_account_app(repo.clone()).await;
        let request = Request::builder()
            .method("POST")
            .uri("/internal/blink/accounts")
            .header(
                "authorization",
                format!("Bearer {}", internal_test_token_with_scope("accounts:read")),
            )
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&valid_create_blink_account_payload())
                    .expect("request serializes"),
            ))
            .expect("request builds");

        let response = app.oneshot(request).await.expect("route responds");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body reads");
        let body: Value = serde_json::from_slice(&body).expect("response body is JSON");

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        assert_eq!(repo.created_blink_account_count(), 0);
    }

    #[tokio::test]
    async fn internal_transfer_to_spark_requires_transfer_scope() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) = post_internal_transfer_to_spark(
            app,
            valid_internal_transfer_to_spark_payload(),
            "blink:accounts:create accounts:read",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        assert!(repo.resolve_calls().is_empty());
        assert_eq!(repo.blink_to_spark_transfer_count(), 0);
    }

    #[tokio::test]
    async fn transfer_route_rejects_invalid_scope_before_side_effects_test_01() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) = post_internal_transfer_to_spark(
            app,
            valid_internal_transfer_to_spark_payload(),
            "accounts:read",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        assert!(
            repo.resolve_calls().is_empty(),
            "scope failures must happen before repository lookups"
        );
        assert_eq!(repo.blink_to_spark_transfer_count(), 0);
    }

    #[tokio::test]
    async fn internal_transfer_to_spark_rejects_invalid_destination_pubkey_without_transfer() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;
        let mut payload = valid_internal_transfer_to_spark_payload();
        payload.destination_spark_pubkey = "not-a-pubkey".to_string();

        let (status, body) = post_internal_transfer_to_spark(
            app,
            payload,
            crate::internal_auth::SCOPE_TRANSFER_WRITE,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": INTERNAL_ERROR_INVALID_REQUEST}));
        assert!(repo.resolve_calls().is_empty());
        assert_eq!(repo.blink_to_spark_transfer_count(), 0);
    }

    #[tokio::test]
    async fn internal_transfer_to_spark_missing_scope_rejects_malformed_json_before_parsing() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) =
            post_internal_transfer_to_spark_raw(app, "{", "blink:accounts:create accounts:read")
                .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        assert!(repo.resolve_calls().is_empty());
        assert_eq!(repo.blink_to_spark_transfer_count(), 0);
    }

    #[tokio::test]
    async fn internal_transfer_to_spark_rejects_spark_owned_source() {
        let repo = MockRepository::default().with_resolved_recipient(spark_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) = post_internal_transfer_to_spark(
            app,
            valid_internal_transfer_to_spark_payload(),
            crate::internal_auth::SCOPE_TRANSFER_WRITE,
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": INTERNAL_ERROR_INVALID_REQUEST}));
        assert_eq!(repo.blink_to_spark_transfer_count(), 0);
    }

    #[tokio::test]
    async fn transfer_route_rejects_invalid_ownership_before_side_effects_test_01() {
        let repo = MockRepository::default().with_resolved_recipient(spark_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) = post_internal_transfer_to_spark(
            app,
            valid_internal_transfer_to_spark_payload(),
            crate::internal_auth::SCOPE_TRANSFER_WRITE,
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": INTERNAL_ERROR_INVALID_REQUEST}));
        assert_eq!(
            repo.blink_to_spark_transfer_count(),
            0,
            "non-Blink owners must not reach transfer side effects"
        );
    }

    #[tokio::test]
    async fn internal_transfer_to_spark_moves_blink_identifier_to_spark() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_transfer_to_spark_app(repo.clone()).await;

        let (status, body) = post_internal_transfer_to_spark(
            app,
            valid_internal_transfer_to_spark_payload(),
            crate::internal_auth::SCOPE_TRANSFER_WRITE,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["domain"], "example.com");
        assert_eq!(body["identifier"], "alice");
        assert_eq!(body["provider"], "spark");
        assert_eq!(
            body["spark_pubkey"],
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(body["lightning_address"], "alice@example.com");
        assert_eq!(body["lnurl"], "lnurlp://example.com/lnurlp/alice");
        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "alice".to_string())]
        );
        assert_eq!(repo.blink_to_spark_transfers().len(), 1);
        let transfer = repo.blink_to_spark_transfers().remove(0);
        assert_eq!(transfer.domain, "example.com");
        assert_eq!(transfer.identifier, "alice");
        assert_eq!(transfer.source_account_id, "acct_blink_lookup");
        assert_eq!(
            transfer.destination_spark_pubkey,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(transfer.description, "Moved to Spark");
    }

    #[tokio::test]
    async fn internal_identifier_lookup_blink_parses_btc_modifier_before_repository_lookup() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_lookup_app(repo.clone()).await;

        let (status, body) = get_internal_identifier(
            app,
            "/internal/domains/example.com/identifiers/alice+btc",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "alice".to_string())]
        );
        assert_eq!(body["provider"], "blink");
        assert_eq!(body["account_id"], "acct_blink_lookup");
        assert_eq!(body["domain"], "example.com");
        assert_eq!(body["identifier"], "alice");
        assert_eq!(body["identifier_kind"], "username");
        assert_eq!(body["description"], "Alice Blink account");
        assert_eq!(body["requested_wallet"], "btc");
        assert_eq!(
            body["provider_details"]["blink_account_id"],
            "blink_account_123"
        );
        assert_eq!(body["provider_details"]["btc_wallet_id"], "btc_wallet_123");
        assert_eq!(body["provider_details"]["usd_wallet_id"], "usd_wallet_123");
        assert_eq!(body["provider_details"]["default_wallet"], "usd");
        assert!(
            body["provider_details"]
                .get("spark_pubkey")
                .is_none_or(Value::is_null)
        );
    }

    #[tokio::test]
    async fn internal_identifier_lookup_spark_returns_spark_details_and_usd_wallet_intent() {
        let repo = MockRepository::default().with_resolved_recipient(spark_resolved_recipient());
        let app = internal_lookup_app(repo.clone()).await;

        let (status, body) = get_internal_identifier(
            app,
            "/internal/domains/Example.COM/identifiers/bob+usd",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "bob".to_string())]
        );
        assert_eq!(body["provider"], "spark");
        assert_eq!(body["account_id"], "acct_spark_lookup");
        assert_eq!(body["requested_wallet"], "usd");
        assert_eq!(body["provider_details"]["spark_pubkey"], "spark_pubkey_123");
        assert!(
            body["provider_details"]
                .get("blink_account_id")
                .is_none_or(Value::is_null)
        );
    }

    #[tokio::test]
    async fn internal_identifier_lookup_requires_accounts_read_scope_before_repository_lookup() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_lookup_app(repo.clone()).await;

        let (status, body) = get_internal_identifier(
            app,
            "/internal/domains/example.com/identifiers/alice",
            internal_test_token_with_scope("blink:accounts:create"),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        assert!(repo.resolve_calls().is_empty());
    }

    #[tokio::test]
    async fn internal_identifier_lookup_returns_not_found_for_missing_identifier() {
        let repo = MockRepository::default();
        let app = internal_lookup_app(repo.clone()).await;

        let (status, body) = get_internal_identifier(
            app,
            "/internal/domains/example.com/identifiers/alice",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, json!({"error": "not_found"}));
        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "alice".to_string())]
        );
    }

    #[tokio::test]
    async fn internal_identifier_lookup_rejects_invalid_domain_and_identifier() {
        let repo = MockRepository::default();
        let app = internal_lookup_app(repo.clone()).await;

        let (domain_status, domain_body) = get_internal_identifier(
            app.clone(),
            "/internal/domains/%20%20/identifiers/alice",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;
        let (identifier_status, identifier_body) = get_internal_identifier(
            app,
            "/internal/domains/example.com/identifiers/alice+eur",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;

        assert_eq!(domain_status, StatusCode::BAD_REQUEST);
        assert_eq!(domain_body, json!({"error": "invalid_domain"}));
        assert_eq!(identifier_status, StatusCode::BAD_REQUEST);
        assert_eq!(identifier_body, json!({"error": "invalid_identifier"}));
        assert!(repo.resolve_calls().is_empty());
    }

    #[tokio::test]
    async fn rejected_rpc_style_identifier_lookup_route_is_not_mounted() {
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let app = internal_lookup_app(repo.clone()).await;

        let (status, _body) = get_internal_identifier(
            app,
            "/internal/accounts/by-identifier/alice?domain=example.com",
            internal_test_token_with_scope("accounts:read"),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(repo.resolve_calls().is_empty());
    }
}
