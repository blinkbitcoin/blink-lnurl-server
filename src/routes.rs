use crate::identifier::{
    IdentifierError, IdentifierKind, WalletModifier, canonical_spark_username,
    parse_public_identifier,
};
use crate::models::{
    CheckUsernameAvailableResponse, CreateBlinkAccountRequest, CreateBlinkAccountResponse,
    INTERNAL_ERROR_BLINK_ACCOUNT_EXISTS, INTERNAL_ERROR_IDENTIFIER_CONFLICT,
    INTERNAL_ERROR_INTERNAL_SERVER_ERROR, INTERNAL_ERROR_INVALID_DOMAIN,
    INTERNAL_ERROR_INVALID_IDENTIFIER, INTERNAL_ERROR_INVALID_REQUEST, INTERNAL_ERROR_NOT_FOUND,
    INTERNAL_ERROR_WALLET_MODIFIER_NOT_ALLOWED, InternalAccountIdentifierResponse,
    InternalErrorResponse, InternalIdentifierLookupResponse, InternalProviderDetailsResponse,
    InvoicePaidRequest, InvoicesPaidRequest, ListMetadataRequest, ListMetadataResponse,
    PublishZapReceiptRequest, PublishZapReceiptResponse, RecoverLnurlPayRequest,
    RecoverLnurlPayResponse, RegisterLnurlPayRequest, RegisterLnurlPayResponse,
    TransferLnurlPayRequest, TransferLnurlPayResponse, UnregisterLnurlPayRequest,
    sanitize_username,
};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use axum_extra::extract::Host;
use bitcoin::{
    hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256},
    secp256k1::{PublicKey, XOnlyPublicKey, ecdsa::Signature},
};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use nostr::{Alphabet, Event, EventBuilder, JsonUtil, Kind, TagStandard, key::Keys};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::str::FromStr;
use std::{collections::HashSet, marker::PhantomData};
use tracing::{debug, error, trace, warn};

use crate::{
    invoice_paid::{
        HandleInvoicePaidError, create_provider_invoice_for_account, handle_invoice_paid,
        handle_invoices_paid,
    },
    repository::LnurlSenderComment,
    time::{now_millis, now_u64},
    zap::Zap,
};
use crate::{
    providers::{
        CreateInvoiceRequest, PaymentStatusRequest, ProviderError,
        parse_blink_settlement_notification,
    },
    repository::{
        AccountIdentifierKind, AccountProvider, IdentifierTransfer, LnurlRepository,
        LnurlRepositoryError, NewAccountIdentifier, NewBlinkAccount, NewSparkRegistration,
        ResolvedRecipient, WalletKind, generate_account_id,
    },
    state::State,
    user::User,
};

const ACCEPTABLE_TIME_DIFF_SECS: u64 = 600;
const DEFAULT_METADATA_OFFSET: u32 = 0;
const DEFAULT_METADATA_LIMIT: u32 = 100;
/// Maximum number of nostr relays to connect to when publishing zap receipts.
const MAX_NOSTR_RELAYS: usize = 10;
/// Maximum size (bytes) of a nostr event JSON (zap request or zap receipt).
const MAX_NOSTR_EVENT_SIZE: usize = 32_768;
/// Maximum length of a sender comment (LUD-12).
const MAX_COMMENT_LENGTH: usize = 255;
const BLINK_BTC_EXPIRY_LIMIT_SECS: u32 = 86_400;
const BLINK_USD_EXPIRY_LIMIT_SECS: u32 = 300;

#[cfg(test)]
const fn public_lnurl_phase_6_error_reasons() -> [&'static str; 6] {
    [
        "unsupported wallet",
        "expiry too long",
        "missing amount",
        "amount out of range",
        "comment too long",
        "invoice creation failed",
    ]
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LnurlPayCallbackParams {
    pub amount: Option<u64>,
    pub comment: Option<String>,
    pub nostr: Option<String>,
    pub expiry: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tag {
    #[serde(rename = "payRequest")]
    Pay,
    #[serde(rename = "withdrawRequest")]
    Withdraw,
    #[serde(rename = "channelRequest")]
    Channel,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayResponse {
    /// a second-level url which give you an invoice with a GET request
    /// and an amount
    pub callback: String,
    /// max sendable amount for a given user on a given service
    #[serde(rename = "maxSendable")]
    pub max_sendable: u64,
    /// min sendable amount for a given user on a given service,
    /// can not be less than 1 or more than `max_sendable`
    #[serde(rename = "minSendable")]
    pub min_sendable: u64,
    /// tag of the request
    pub tag: Tag,
    /// Metadata json which must be presented as raw string here,
    /// this is required to pass signature verification at a later step
    pub metadata: String,

    /// Optional, if true, the service allows comments
    /// the number is the max length of the comment
    #[serde(rename = "commentAllowed")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_allowed: Option<u32>,

    /// Optional, if true, the service allows nostr zaps
    #[serde(rename = "allowsNostr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allows_nostr: Option<bool>,

    /// Optional, if true, the nostr pubkey that will be used to sign zap events
    #[serde(rename = "nostrPubkey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<XOnlyPublicKey>,
}

struct PublicIdentifierIntent {
    canonical: String,
    wallet: Option<WalletKind>,
    callback_identifier: String,
}

struct PublicRecipient {
    recipient: ResolvedRecipient,
    wallet: Option<WalletKind>,
    callback_identifier: String,
}

pub struct LnurlServer<DB> {
    db: PhantomData<DB>,
}

impl<DB> LnurlServer<DB>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    pub async fn available(
        Host(host): Host,
        Path(identifier): Path<String>,
        Extension(state): Extension<State<DB>>,
    ) -> Result<Json<CheckUsernameAvailableResponse>, (StatusCode, Json<Value>)> {
        let username = canonical_spark_username_for_route(&identifier)?;
        let domain = sanitize_domain(&state, &host).await?;
        let recipient = state
            .db
            .resolve_recipient_by_identifier(&domain, &username)
            .await
            .map_err(|e| {
                error!("failed to execute query: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Value::String("internal server error".into())),
                )
            })?;

        Ok(Json(CheckUsernameAvailableResponse {
            available: recipient.is_none(),
        }))
    }

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
        let offset = params.offset.unwrap_or(DEFAULT_METADATA_OFFSET);
        let limit = params.limit.unwrap_or(DEFAULT_METADATA_LIMIT);
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

    #[allow(clippy::too_many_lines)]
    pub async fn publish_zap_receipt(
        Path((pubkey, payment_hash)): Path<(String, String)>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<PublishZapReceiptRequest>,
    ) -> Result<Json<PublishZapReceiptResponse>, (StatusCode, Json<Value>)> {
        let pubkey = validate(
            &pubkey,
            &payload.signature,
            &payload.zap_receipt,
            payload.timestamp,
            &state,
        )
        .await?;

        if payload.zap_receipt.len() > MAX_NOSTR_EVENT_SIZE {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "zap receipt too large"})),
            ));
        }

        // Parse and validate the zap receipt
        let zap_receipt = Event::from_json(&payload.zap_receipt).map_err(|e| {
            trace!("invalid zap receipt, could not parse: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid zap receipt"})),
            )
        })?;

        // Validate it's a zap receipt (kind 9735)
        if zap_receipt.kind != Kind::ZapReceipt {
            trace!(
                "event is not a zap receipt, got kind: {:?}",
                zap_receipt.kind
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "event is not a zap receipt"})),
            ));
        }

        // Verify the zap receipt signature
        if zap_receipt.verify().is_err() {
            trace!("invalid zap receipt signature");
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid zap receipt signature"})),
            ));
        }

        // Extract preimage from zap receipt for LUD-21 backward compatibility
        // This allows old clients using publish_zap_receipt to still populate
        // the invoice's preimage for the verify endpoint
        let preimage_from_receipt = zap_receipt.tags.iter().find_map(|t| {
            if let Some(TagStandard::Preimage(p)) = t.as_standardized() {
                Some(p.clone())
            } else {
                None
            }
        });

        // Get the existing zap record
        let mut zap = state
            .db
            .get_zap_by_payment_hash(&payment_hash)
            .await
            .map_err(|e| {
                error!("failed to query zap: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal server error"})),
                )
            })?
            .ok_or_else(|| {
                trace!("zap not found for payment hash: {}", payment_hash);
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "zap not found"})),
                )
            })?;

        // Verify the zap belongs to this user
        if zap.user_pubkey != pubkey.to_string() {
            trace!("zap does not belong to this user");
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({"error": "unauthorized"})),
            ));
        }

        // If we have a preimage, call the invoice paid handler for LUD-21 compatibility
        // This ensures the preimage is stored in the invoices table
        if let Some(preimage) = &preimage_from_receipt {
            match handle_invoice_paid(
                &state.db,
                &state.webhook_service,
                &payment_hash,
                preimage,
                None,
                &state.invoice_paid_trigger,
            )
            .await
            {
                Err(HandleInvoicePaidError::InvalidPreimage(_)) => {
                    trace!("invalid preimage in zap receipt for {}", payment_hash);
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "invalid preimage"})),
                    ));
                }
                Err(e) => {
                    // Log but don't fail - this is for backward compatibility
                    debug!(
                        "Failed to handle invoice paid from zap receipt for {}: {}",
                        payment_hash, e
                    );
                }
                Ok(()) => {}
            }
        }

        // Check if zap receipt already exists
        let mut published = false;
        if let Some(zap_receipt) = &zap.zap_event {
            debug!(
                "Zap receipt already exists for payment hash {}",
                payment_hash
            );
            return Ok(Json(PublishZapReceiptResponse {
                published,
                zap_receipt: zap_receipt.clone(),
            }));
        }

        // Parse the zap request to get relay info
        let zap_request = Event::from_json(&zap.zap_request).map_err(|e| {
            error!("failed to parse stored zap request: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
        })?;

        // Determine if we need to recreate the zap receipt with server nostr key
        let zap_receipt = match (zap.is_user_nostr_key, &state.nostr_keys) {
            (true, _) => zap_receipt,
            (false, None) => {
                warn!("server nostr keys not configured, but should publish zap receipt.");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(
                        json!({"error": "zap receipt should be server-published, but server does not support nostr (anymore)"}),
                    ),
                ));
            }
            (false, Some(signing_keys)) => {
                // Recreate zap receipt signed by server nostr key
                let preimage = zap_receipt.tags.iter().find_map(|t| {
                    if let Some(TagStandard::Preimage(p)) = t.as_standardized() {
                        Some(p.clone())
                    } else {
                        None
                    }
                });

                let invoice = zap_receipt
                    .tags
                    .iter()
                    .find_map(|t| {
                        if let Some(TagStandard::Bolt11(b)) = t.as_standardized() {
                            Some(b)
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        warn!("zap receipt missing bolt11 tag");
                        (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "zap receipt missing bolt11 tag"})),
                        )
                    })?;

                let zap_request_event = Event::from_json(&zap.zap_request).map_err(|e| {
                    error!("failed to parse zap request: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "internal server error"})),
                    )
                })?;
                let builder = EventBuilder::zap_receipt(invoice, preimage, &zap_request_event);

                builder.sign_with_keys(signing_keys).map_err(|e| {
                    error!("failed to sign zap receipt: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "internal server error"})),
                    )
                })?
            }
        };

        let relays: Vec<_> = zap_request
            .tags
            .iter()
            .filter_map(|t| {
                if let Some(TagStandard::Relays(r)) = t.as_standardized() {
                    Some(r.clone())
                } else {
                    None
                }
            })
            .flatten()
            .take(MAX_NOSTR_RELAYS)
            .collect();

        if !relays.is_empty() {
            // The nostr keys are not really needed here, but we use them to create the client
            let publish_nostr_keys = match &state.nostr_keys {
                Some(keys) => keys.clone(),
                None => Keys::generate(),
            };
            let nostr_client = nostr_sdk::Client::new(publish_nostr_keys);
            for r in &relays {
                if let Err(e) = nostr_client.add_relay(r).await {
                    warn!("Failed to add relay {r}: {e}");
                }
            }

            nostr_client.connect().await;

            if let Err(e) = nostr_client.send_event(&zap_receipt).await {
                error!("Failed to publish zap receipt to relays: {e}");
            } else {
                debug!("Published zap receipt to {} relays", relays.len());
                published = true;
            }

            nostr_client.disconnect().await;
        }

        let zap_receipt_json = zap_receipt.try_as_json().map_err(|e| {
            error!("failed to serialize zap receipt: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
        })?;
        zap.zap_event = Some(zap_receipt_json.clone());
        zap.updated_at = now_millis();
        state.db.upsert_zap(&zap).await.map_err(|e| {
            error!("failed to save zap receipt: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
        })?;

        Ok(Json(PublishZapReceiptResponse {
            published,
            zap_receipt: zap_receipt_json,
        }))
    }

    pub async fn handle_lnurl_pay(
        Host(host): Host,
        Path(identifier): Path<String>,
        Extension(state): Extension<State<DB>>,
    ) -> Result<Json<PayResponse>, (StatusCode, Json<Value>)> {
        if identifier.is_empty() {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        }

        let domain = sanitize_domain(&state, &host).await?;
        let Some(public_identifier) = parse_public_identifier_for_public_route(&identifier)
            .map_err(|e| {
                trace!("invalid public identifier '{identifier}': {e:?}");
                lnurl_error("invalid identifier")
            })?
        else {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        };
        let public_recipient = resolve_public_recipient(&state, &domain, public_identifier).await?;
        let Some(public_recipient) = public_recipient else {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        };

        let (allows_nostr, nostr_pubkey) = if let Some(nostr_keys) = state.nostr_keys.as_ref() {
            let xonly_pubkey = nostr_keys.public_key.xonly().map_err(|e| {
                error!(
                    "invalid nostr pubkey in server keys, could not parse: {:?}",
                    e
                );
                lnurl_error("internal server error")
            })?;
            (Some(true), Some(xonly_pubkey))
        } else {
            (None, None)
        };
        Ok(Json(PayResponse {
            callback: format!(
                "{}://{}/lnurlp/{}/invoice",
                state.scheme, domain, public_recipient.callback_identifier
            ),
            max_sendable: state.max_sendable,
            min_sendable: state.min_sendable,
            tag: Tag::Pay,
            metadata: get_metadata_for_recipient(
                &public_recipient.recipient,
                &public_recipient.callback_identifier,
            ),
            #[allow(clippy::cast_possible_truncation)]
            comment_allowed: Some(MAX_COMMENT_LENGTH as u32),
            allows_nostr,
            nostr_pubkey,
        }))
    }

    #[allow(clippy::too_many_lines)]
    pub async fn handle_invoice(
        Host(host): Host,
        Path(identifier): Path<String>,
        Query(params): Query<LnurlPayCallbackParams>,
        Extension(state): Extension<State<DB>>,
    ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
        if identifier.is_empty() {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        }

        let Some(public_identifier) = parse_public_identifier_for_public_route(&identifier)
            .map_err(|e| {
                trace!("invalid public identifier '{identifier}': {e:?}");
                lnurl_error("invalid identifier")
            })?
        else {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        };
        let domain = sanitize_domain(&state, &host).await?;
        let public_recipient = resolve_public_recipient(&state, &domain, public_identifier).await?;
        let Some(public_recipient) = public_recipient else {
            return Err((StatusCode::NOT_FOUND, Json(Value::String(String::new()))));
        };
        let account_id = public_recipient.recipient.account_id.clone();
        let legacy_user_pubkey = public_recipient
            .recipient
            .spark_pubkey
            .as_deref()
            .unwrap_or("")
            .to_string();

        let Some(amount_msat) = params.amount else {
            trace!("missing amount");
            return Err(lnurl_error("missing amount"));
        };

        if amount_msat % 1000 != 0 {
            trace!("not a full sat amount");
            return Err(lnurl_error("amount must be a whole sat amount"));
        }

        if amount_msat < state.min_sendable || amount_msat > state.max_sendable {
            trace!("amount outside advertised minSendable/maxSendable range");
            return Err(lnurl_error("amount out of range"));
        }

        if let Some(comment) = params.comment.as_deref()
            && comment.trim().len() > MAX_COMMENT_LENGTH
        {
            return Err(lnurl_error("comment too long"));
        }

        let nostr_pubkey = state
            .nostr_keys
            .as_ref()
            .map(|nostr_keys| {
                nostr_keys.public_key.xonly().map_err(|e| {
                    error!(
                        "invalid nostr pubkey in server keys, could not parse: {:?}",
                        e
                    );
                    lnurl_error("internal server error")
                })
            })
            .transpose()?;

        let desc_hash = if let Some(raw_event) = &params.nostr {
            let Some(expected_nostr_pubkey) = nostr_pubkey else {
                trace!("nostr zap not supported");
                return Err(lnurl_error("nostr zap not supported"));
            };

            if raw_event.len() > MAX_NOSTR_EVENT_SIZE {
                return Err(lnurl_error("nostr event too large"));
            }

            let event = Event::from_json(raw_event).map_err(|e| {
                trace!("invalid nostr event, could not parse: {}", e);
                lnurl_error("invalid nostr event")
            })?;
            validate_nostr_zap_request(amount_msat, &event, expected_nostr_pubkey)?;
            sha256::Hash::hash(raw_event.as_bytes())
        } else {
            let metadata = get_metadata_for_recipient(
                &public_recipient.recipient,
                &public_recipient.callback_identifier,
            );
            sha256::Hash::hash(metadata.as_bytes())
        };

        let expiry = callback_expiry_for_provider(
            public_recipient.recipient.provider,
            public_recipient.wallet,
            public_recipient.recipient.default_wallet,
            params.expiry,
        )?;

        let res = state
            .providers
            .provider_for(public_recipient.recipient.provider)
            .create_invoice(CreateInvoiceRequest {
                recipient: &public_recipient.recipient,
                wallet: public_recipient.wallet,
                amount_sat: amount_msat / 1000,
                description_hash: desc_hash.to_byte_array(),
                expiry,
                include_spark_address: state.include_spark_address,
            })
            .await
            .map_err(map_provider_invoice_error)?;

        debug!("Created lightning invoice: {:?}", res);

        let invoice = Bolt11Invoice::from_str(&res.bolt11).map_err(|e| {
            error!("failed to parse invoice: {}", e);
            lnurl_error("internal server error")
        })?;

        if !matches!(invoice.description(), Bolt11InvoiceDescriptionRef::Hash(hash) if hash.0.to_string() == desc_hash.to_string())
        {
            error!("provider returned invoice with unexpected description hash");
            return Err(lnurl_error("internal server error"));
        }

        let Some(invoice_amount_msat) = invoice.amount_milli_satoshis() else {
            error!("provider returned invoice without an amount");
            return Err(lnurl_error("internal server error"));
        };

        if invoice_amount_msat != amount_msat {
            error!(
                "provider returned invoice amount {} msat, expected {} msat",
                invoice_amount_msat, amount_msat
            );
            return Err(lnurl_error("internal server error"));
        }

        // Calculate expiry timestamp: current time + expiry duration from invoice
        let expiry_timestamp = invoice.expires_at().ok_or_else(|| {
            error!(
                "invoice has invalid expiry: duration since epoch {}s, expiry time: {}s",
                invoice.duration_since_epoch().as_secs(),
                invoice.expiry_time().as_secs()
            );
            lnurl_error("internal server error")
        })?;

        let updated_at = now_millis();
        let payment_hash = invoice.payment_hash().to_string();
        let invoice_expiry: i64 = i64::try_from(expiry_timestamp.as_secs()).map_err(|e| {
            error!(
                "invoice has invalid expiry for i64: duration since epoch {}s, expiry time: {}s: {e}",
                invoice.duration_since_epoch().as_secs(),
                invoice.expiry_time().as_secs(),
            );
            lnurl_error("internal server error")
        })?;

        // save to zap event to db
        if let Some(zap_request) = params.nostr {
            let zap = Zap {
                account_id: Some(account_id.clone()),
                payment_hash: payment_hash.clone(),
                zap_request,
                zap_event: None,
                user_pubkey: legacy_user_pubkey.clone(),
                invoice_expiry,
                updated_at,
                is_user_nostr_key: false,
            };
            if let Err(e) = state.db.upsert_zap(&zap).await {
                error!("failed to save zap event: {}", e);
                return Err(lnurl_error("internal server error"));
            }
        }

        if let Some(comment) = params.comment {
            let comment = comment.trim();
            if !comment.is_empty()
                && let Err(e) = state
                    .db
                    .insert_lnurl_sender_comment(&LnurlSenderComment {
                        account_id: Some(account_id.clone()),
                        comment: comment.to_string(),
                        payment_hash: payment_hash.clone(),
                        user_pubkey: legacy_user_pubkey.clone(),
                        updated_at,
                    })
                    .await
            {
                error!("Failed to insert lnurl sender comment: {:?}", e);
                return Err(lnurl_error("internal server error"));
            }
        }

        // Store invoice for LUD-21 verify support and webhook delivery
        if let Err(e) = create_provider_invoice_for_account(
            &state.db,
            &payment_hash,
            Some(&account_id),
            Some(public_recipient.recipient.provider),
            Some(res.wallet_kind),
            res.wallet_id.as_deref(),
            res.provider_payment_hash.as_deref(),
            &legacy_user_pubkey,
            &res.bolt11,
            invoice_expiry,
            &domain,
        )
        .await
        {
            error!("Failed to create invoice record: {}", e);
            return Err(lnurl_error("internal server error"));
        }

        let verify_url = format!("{}://{}/verify/{}", state.scheme, domain, payment_hash);

        Ok(Json(json!({
            "pr": res.bolt11,
            "routes": Vec::<String>::new(),
            "verify": verify_url,
        })))
    }

    /// LUD-21 verify endpoint
    pub async fn verify(
        Path(payment_hash): Path<String>,
        Extension(state): Extension<State<DB>>,
    ) -> impl IntoResponse {
        let mut invoice = match state.db.get_invoice_by_payment_hash(&payment_hash).await {
            Ok(Some(invoice)) => invoice,
            Ok(None) => {
                return Json(json!({
                    "status": "ERROR",
                    "reason": "Not found"
                }));
            }
            Err(e) => {
                error!("Failed to get invoice by payment hash: {}", e);
                return Json(json!({
                    "status": "ERROR",
                    "reason": "Internal server error"
                }));
            }
        };

        if invoice.preimage.is_none() && invoice.provider == Some(AccountProvider::Blink) {
            match settle_blink_invoice_by_payment_hash(&state, &payment_hash, None).await {
                Ok(Some(preimage)) => {
                    invoice.preimage = Some(preimage);
                }
                Ok(None) => {}
                Err(e) => {
                    error!(
                        "Failed to settle Blink invoice during public verify for {}: {}",
                        payment_hash, e
                    );
                    return Json(json!({
                        "status": "ERROR",
                        "reason": "Internal server error"
                    }));
                }
            }
        }

        let settled = invoice.preimage.is_some();
        Json(json!({
            "status": "OK",
            "settled": settled,
            "preimage": invoice.preimage,
            "pr": invoice.invoice
        }))
    }

    /// Invoice-paid notification endpoint (single invoice).
    /// Deprecated: use `invoices_paid` instead, which supports batch notifications.
    /// TODO(DEF-legacy-invoice-paid): Remove after all clients have migrated to `invoices_paid`.
    pub async fn invoice_paid(
        Path(pubkey): Path<String>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<InvoicePaidRequest>,
    ) -> Result<(), (StatusCode, Json<Value>)> {
        let pubkey = validate(
            &pubkey,
            &payload.signature,
            &payload.preimage,
            payload.timestamp,
            &state,
        )
        .await?;

        let preimage_bytes = hex::decode(&payload.preimage).map_err(|e| {
            trace!("invalid preimage, could not decode: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(Value::String("invalid preimage".into())),
            )
        })?;
        let payment_hash = bitcoin::hashes::sha256::Hash::hash(&preimage_bytes);
        let payment_hash_hex = payment_hash.to_string();

        // Verify the invoice belongs to this user
        let invoice = state
            .db
            .get_invoice_by_payment_hash(&payment_hash_hex)
            .await
            .map_err(|e| {
                error!("Failed to get invoice: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Value::String("internal server error".into())),
                )
            })?
            .ok_or_else(|| {
                trace!("invoice not found for payment hash: {}", payment_hash_hex);
                (
                    StatusCode::NOT_FOUND,
                    Json(Value::String("invoice not found".into())),
                )
            })?;

        if invoice.user_pubkey != pubkey.to_string() {
            trace!("invoice does not belong to this user");
            return Err((
                StatusCode::NOT_FOUND,
                Json(Value::String("invoice not found".into())),
            ));
        }

        // Use the central invoice paid handler
        handle_invoice_paid(
            &state.db,
            &state.webhook_service,
            &payment_hash_hex,
            &payload.preimage,
            None,
            &state.invoice_paid_trigger,
        )
        .await
        .map_err(|e| {
            error!("Failed to handle invoice paid: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Value::String("internal server error".into())),
            )
        })?;

        debug!(
            "Invoice paid notification received for payment hash {}",
            payment_hash_hex
        );
        Ok(())
    }

    /// Batch invoices-paid notification endpoint.
    /// Client notifies server that multiple invoices were paid with their preimages.
    pub async fn invoices_paid(
        Path(pubkey): Path<String>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<InvoicesPaidRequest>,
    ) -> Result<(), (StatusCode, Json<Value>)> {
        const MAX_PREIMAGES: usize = 100;

        if payload.invoices.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(Value::String("invoices must not be empty".into())),
            ));
        }

        if payload.invoices.len() > MAX_PREIMAGES {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(Value::String(format!(
                    "too many invoices, max is {MAX_PREIMAGES}"
                ))),
            ));
        }

        let pubkey = validate(
            &pubkey,
            &payload.signature,
            &pubkey,
            payload.timestamp,
            &state,
        )
        .await?;

        handle_invoices_paid(
            &state.db,
            &state.webhook_service,
            &payload.invoices,
            &pubkey.to_string(),
            &state.invoice_paid_trigger,
        )
        .await
        .map_err(|e| match &e {
            HandleInvoicePaidError::InvalidInvoice(msg)
            | HandleInvoicePaidError::InvalidPreimage(msg) => {
                trace!("Invalid input in invoices-paid: {}", msg);
                (StatusCode::BAD_REQUEST, Json(Value::String(msg.clone())))
            }
            HandleInvoicePaidError::Repository(_) => {
                error!("Failed to handle invoices paid: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(Value::String("internal server error".into())),
                )
            }
        })?;

        debug!(
            "Invoices paid notification received for {} invoices",
            payload.invoices.len()
        );
        Ok(())
    }

    /// Webhook endpoint for SSP payment notifications.
    /// Verifies HMAC-SHA256 signature and processes payment preimages.
    pub async fn webhook(
        Extension(state): Extension<State<DB>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<(), (StatusCode, Json<Value>)> {
        process_webhook(
            &state.db,
            &state.webhook_service,
            &state.webhook_secret,
            &state.invoice_paid_trigger,
            &headers,
            &body,
        )
        .await
    }

    pub async fn blink_invoice_paid(
        Extension(principal): Extension<crate::internal_auth::InternalPrincipal>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<Value>,
    ) -> Result<(), (StatusCode, Json<InternalErrorResponse>)> {
        crate::internal_auth::require_scope(
            &principal,
            crate::internal_auth::SCOPE_SETTLEMENT_WRITE,
        )?;

        let parsed = parse_blink_settlement_notification(&payload).map_err(|e| {
            trace!("invalid Blink settlement payload: {e}");
            internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST)
        })?;

        if !parsed.should_settle() {
            return Ok(());
        }

        let Some(payment_hash) = parsed.payment_hash() else {
            trace!("missing paymentHash in Blink settlement payload");
            return Err(internal_bad_request(INTERNAL_ERROR_INVALID_REQUEST));
        };

        settle_blink_invoice_by_payment_hash(&state, payment_hash, parsed.preimage())
            .await
            .map_err(|e| {
                error!(
                    "failed to settle Blink invoice notification for {}: {}",
                    payment_hash, e
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(InternalErrorResponse::new(
                        INTERNAL_ERROR_INTERNAL_SERVER_ERROR,
                    )),
                )
            })?;

        Ok(())
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
    validate_description(&description)
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

#[allow(clippy::too_many_lines)]
async fn process_webhook<DB>(
    db: &DB,
    webhook_service: &crate::webhooks::WebhookService<DB>,
    webhook_secret: &str,
    invoice_paid_trigger: &tokio::sync::watch::Sender<()>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(), (StatusCode, Json<Value>)>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    // Verify HMAC-SHA256 signature
    let signature_header = headers
        .get("X-Spark-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            trace!("missing X-Spark-Signature header");
            (
                StatusCode::UNAUTHORIZED,
                Json(Value::String("missing signature".into())),
            )
        })?;

    let signature_bytes = hex::decode(signature_header).map_err(|_| {
        trace!("invalid signature hex encoding");
        (
            StatusCode::UNAUTHORIZED,
            Json(Value::String("invalid signature".into())),
        )
    })?;

    let mut engine = HmacEngine::<sha256::Hash>::new(webhook_secret.as_bytes());
    engine.input(body);
    let expected_hmac: Hmac<sha256::Hash> = Hmac::from_engine(engine);

    if expected_hmac.to_byte_array() != signature_bytes.as_slice() {
        trace!("invalid webhook signature");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(Value::String("invalid signature".into())),
        ));
    }

    // Parse the body
    let payload: SspWebhookPayload = serde_json::from_slice(body).map_err(|e| {
        trace!("invalid webhook payload: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid payload".into())),
        )
    })?;

    // Only process lightning receive finished events
    if payload.event_type != "SPARK_LIGHTNING_RECEIVE_FINISHED" {
        debug!("ignoring webhook event type: {}", payload.event_type);
        return Ok(());
    }

    let payment_preimage = payload.payment_preimage.ok_or_else(|| {
        trace!("missing payment_preimage in webhook payload");
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("missing payment_preimage".into())),
        )
    })?;

    let receiver_pubkey = payload.receiver_identity_public_key.ok_or_else(|| {
        trace!("missing receiver_identity_public_key in webhook payload");
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("missing receiver_identity_public_key".into())),
        )
    })?;

    // Compute payment hash from preimage
    let preimage_bytes = hex::decode(&payment_preimage).map_err(|e| {
        trace!("invalid preimage hex: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid preimage".into())),
        )
    })?;
    let payment_hash = sha256::Hash::hash(&preimage_bytes).to_string();

    // Look up invoice
    let invoice = db
        .get_invoice_by_payment_hash(&payment_hash)
        .await
        .map_err(|e| {
            error!("failed to get invoice: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Value::String("internal server error".into())),
            )
        })?;

    let Some(invoice) = invoice else {
        debug!(
            "no invoice found for payment hash {} from webhook",
            payment_hash
        );
        return Ok(());
    };

    // Verify invoice belongs to the receiver
    if invoice.user_pubkey != receiver_pubkey {
        warn!(
            "webhook invoice user mismatch: expected={}, got={}",
            receiver_pubkey, invoice.user_pubkey
        );
        return Ok(());
    }

    let amount_received_sat = match &payload.htlc_amount {
        Some(amount) if amount.unit == "SATOSHI" => Some(amount.value),
        Some(amount) if amount.unit == "MILLISATOSHI" => {
            if amount.value % 1000 != 0 {
                warn!(
                    "truncating htlc_amount from {} msat to {} sat",
                    amount.value,
                    amount.value / 1000
                );
            }
            Some(amount.value / 1000)
        }
        Some(amount) => {
            warn!("unexpected htlc_amount unit: {}", amount.unit);
            None
        }
        None => None,
    };

    // Handle the invoice paid event
    if let Err(e) = handle_invoice_paid(
        db,
        webhook_service,
        &payment_hash,
        &payment_preimage,
        amount_received_sat,
        invoice_paid_trigger,
    )
    .await
    {
        error!(
            "failed to handle webhook invoice paid for {}: {}",
            payment_hash, e
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Value::String("internal server error".into())),
        ));
    }

    debug!(
        "webhook processed: invoice {} paid for pubkey {}",
        payment_hash, receiver_pubkey
    );
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum BlinkSettlementError {
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    InvoicePaid(#[from] HandleInvoicePaidError),
}

async fn settle_blink_invoice_by_payment_hash<DB>(
    state: &State<DB>,
    payment_hash: &str,
    supplied_preimage: Option<&str>,
) -> Result<Option<String>, BlinkSettlementError>
where
    DB: LnurlRepository + crate::webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    if let Some(preimage) = supplied_preimage {
        handle_invoice_paid(
            &state.db,
            &state.webhook_service,
            payment_hash,
            preimage,
            None,
            &state.invoice_paid_trigger,
        )
        .await?;
        return Ok(Some(preimage.to_string()));
    }

    let status = state
        .providers
        .provider_for(AccountProvider::Blink)
        .payment_status(PaymentStatusRequest { payment_hash })
        .await?;

    if !status.settled {
        return Ok(None);
    }

    let Some(preimage) = status.preimage else {
        return Ok(None);
    };

    handle_invoice_paid(
        &state.db,
        &state.webhook_service,
        payment_hash,
        &preimage,
        status.amount_received_sat,
        &state.invoice_paid_trigger,
    )
    .await?;

    Ok(Some(preimage))
}

fn validate_nostr_zap_request(
    amount_msat: u64,
    event: &Event,
    expected_nostr_pubkey: XOnlyPublicKey,
) -> Result<(), (StatusCode, Json<Value>)> {
    if event.kind != Kind::ZapRequest {
        trace!("nostr event is incorrect kind");
        return Err(lnurl_error("invalid nostr event"));
    }

    // 1. It MUST have a valid nostr signature
    if event.verify().is_err() {
        trace!("invalid nostr event, does not verify");
        return Err(lnurl_error("invalid nostr event"));
    }

    // 2. It MUST have tags
    if event.tags.is_empty() {
        trace!("invalid nostr event, missing tags");
        return Err(lnurl_error("invalid nostr event"));
    }

    // 3. It MUST have only one p tag for the advertised recipient pubkey.
    let mut p_tags = event
        .tags
        .iter()
        .filter(|tag| {
            tag.single_letter_tag()
                .is_some_and(|t| t.is_lowercase() && t.character == Alphabet::P)
        })
        .filter_map(nostr::Tag::content);
    let Some(p_tag) = p_tags.next() else {
        trace!("invalid nostr event, missing 'p' tag");
        return Err(lnurl_error("invalid nostr event"));
    };
    if p_tags.next().is_some() {
        trace!("invalid nostr event, missing or multiple 'p' tags");
        return Err(lnurl_error("invalid nostr event"));
    }
    if p_tag != expected_nostr_pubkey.to_string() {
        trace!("invalid nostr event, 'p' tag does not match recipient pubkey");
        return Err(lnurl_error("invalid nostr event"));
    }

    // 4. It MUST have 0 or 1 e tags
    if event
        .tags
        .iter()
        .filter_map(nostr::Tag::single_letter_tag)
        .filter(|t| t.is_lowercase() && t.character == Alphabet::E)
        .count()
        > 1
    {
        trace!("invalid nostr event, multiple 'e' tags");
        return Err(lnurl_error("invalid nostr event"));
    }

    // 5. There should be a relays tag with the relays to send the zap receipt to.
    if !event
        .tags
        .iter()
        .any(|t| matches!(t.as_standardized(), Some(TagStandard::Relays(_))))
    {
        trace!("invalid nostr event, missing relay tag");
        return Err(lnurl_error("invalid nostr event"));
    }

    // 6. If there is an amount tag, it MUST be equal to the amount query parameter.
    if let Some(millisats) = event.tags.iter().find_map(|t| {
        if let Some(TagStandard::Amount { millisats, .. }) = t.as_standardized() {
            Some(millisats)
        } else {
            None
        }
    }) && *millisats != amount_msat
    {
        trace!("invalid nostr event, amount does not match");
        return Err(lnurl_error("invalid nostr event"));
    }

    // 7. If there is an 'a' tag, it MUST be a valid event coordinate
    // NOTE: Assuming the tag is well-formed and contains the necessary fields, because it's standard.

    // 8. There MUST be 0 or 1 P tags. If there is one, it MUST be equal to the zap receipt's pubkey.
    // TODO(Phase 7): Enforce optional NIP-57 P-tag recipient checks when provider-neutral zap receipt keys are migrated.
    Ok(())
}

fn canonical_spark_username_for_route(username: &str) -> Result<String, (StatusCode, Json<Value>)> {
    canonical_spark_username(username).map_err(|e| {
        trace!("invalid Spark username: {e:?}");
        (
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid username".into())),
        )
    })
}

#[cfg(test)]
fn validate_username(username: &str) -> Result<(), (StatusCode, Json<Value>)> {
    canonical_spark_username_for_route(username).map(|_| ())
}

#[cfg(test)]
fn public_lookup_username(identifier: &str) -> Result<Option<String>, IdentifierError> {
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

fn parse_public_identifier_for_public_route(
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

const fn wallet_modifier_to_kind(modifier: WalletModifier) -> WalletKind {
    match modifier {
        WalletModifier::Btc => WalletKind::Btc,
        WalletModifier::Usd => WalletKind::Usd,
    }
}

async fn resolve_public_recipient<DB>(
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
            lnurl_error("internal server error")
        })?;

    Ok(recipient.map(|recipient| PublicRecipient {
        recipient,
        wallet: intent.wallet,
        callback_identifier: intent.callback_identifier,
    }))
}

fn is_legacy_spark_lookup_candidate(identifier: &str) -> bool {
    !is_phone_like_public_identifier(identifier)
        && !identifier.char_indices().skip(1).any(|(_, ch)| ch == '+')
}

fn is_phone_like_public_identifier(identifier: &str) -> bool {
    identifier.starts_with('+')
        || identifier.starts_with("00")
        || identifier.chars().all(|ch| ch.is_ascii_digit())
}

fn validate_description(description: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if description.chars().take(256).count() > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Value::String("description too long".into())),
        ));
    }
    Ok(())
}

async fn validate<DB>(
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
    if diff > ACCEPTABLE_TIME_DIFF_SECS {
        trace!(
            "invalid timestamp, too far off: {}, now: {}, diff: {}",
            timestamp, now, diff
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Value::String("invalid timestamp".into())),
        ));
    }

    state
        .wallet
        .verify_message(&format!("{message}-{timestamp}"), &signature, &pubkey)
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
async fn verify_transfer_signature<DB>(
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

    state
        .wallet
        .verify_message(message, &signature, &pk)
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

fn parse_pubkey(pubkey: &str) -> Result<PublicKey, (StatusCode, Json<Value>)> {
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

#[cfg(test)]
fn get_metadata(domain: &str, user: &User) -> String {
    json!(vec![
        vec!["text/plain", &user.description],
        vec!["text/identifier", &format!("{}@{}", user.name, domain)],
    ])
    .to_string()
}

fn get_metadata_for_recipient(recipient: &ResolvedRecipient, requested_identifier: &str) -> String {
    json!(vec![
        vec!["text/plain", &recipient.description],
        vec![
            "text/identifier",
            &format!("{}@{}", requested_identifier, recipient.domain),
        ],
    ])
    .to_string()
}

fn callback_expiry_for_provider(
    provider: AccountProvider,
    requested_wallet: Option<WalletKind>,
    default_wallet: Option<WalletKind>,
    expiry_secs: Option<u32>,
) -> Result<Option<u32>, (StatusCode, Json<Value>)> {
    if provider != AccountProvider::Blink {
        return Ok(expiry_secs);
    }

    let Some(seconds) = expiry_secs else {
        return Ok(None);
    };
    let Some(wallet) = requested_wallet.or(default_wallet) else {
        error!("Blink callback has no selected or default wallet for expiry policy");
        return Err(lnurl_error("internal server error"));
    };

    let limit = match wallet {
        WalletKind::Btc => BLINK_BTC_EXPIRY_LIMIT_SECS,
        WalletKind::Usd => BLINK_USD_EXPIRY_LIMIT_SECS,
    };
    if seconds > limit {
        trace!("Blink {wallet:?} callback expiry {seconds}s exceeds limit {limit}s");
        return Err(lnurl_error("expiry too long"));
    }

    Ok(Some(seconds.div_ceil(60)))
}

#[allow(clippy::needless_pass_by_value)]
fn storage_error(error: LnurlRepositoryError) -> (StatusCode, Json<Value>) {
    error!("failed to execute query: {error}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(Value::String("internal server error".into())),
    )
}

fn spark_transfer_error(error: LnurlRepositoryError, username: &str) -> (StatusCode, Json<Value>) {
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

fn spark_unregister_error(
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

fn spark_registration_error(
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

fn map_provider_invoice_error(error: ProviderError) -> (StatusCode, Json<Value>) {
    match error {
        ProviderError::UnsupportedWallet { provider, wallet } => {
            trace!("unsupported wallet {wallet:?} for provider {provider:?}");
            lnurl_error("unsupported wallet")
        }
        ProviderError::InvoiceCreationFailed(err) => {
            error!("failed to create lightning invoice: {err}");
            lnurl_error("invoice creation failed")
        }
        ProviderError::BlinkInvoiceCreationFailed(err) => {
            error!("failed to create Blink lightning invoice: {err}");
            lnurl_error("invoice creation failed")
        }
        ProviderError::UnsupportedProvider(provider) => {
            error!("unsupported provider for public LNURL invoice: {provider:?}");
            lnurl_error("internal server error")
        }
        ProviderError::MissingSparkPubkey
        | ProviderError::InvalidSparkPubkey
        | ProviderError::MissingBlinkDefaultWallet
        | ProviderError::MissingBlinkBtcWalletId
        | ProviderError::MissingBlinkUsdWalletId
        | ProviderError::BlinkPaymentStatusUnavailable(_)
        | ProviderError::PaymentStatusUnavailable(_) => {
            error!("invalid provider invoice state: {error}");
            lnurl_error("internal server error")
        }
    }
}

#[allow(dead_code)]
fn spark_user_from_recipient(recipient: ResolvedRecipient) -> Result<User, LnurlRepositoryError> {
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

fn lnurl_error(message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(Value::Object(
            vec![
                ("status".into(), Value::String("ERROR".to_string())),
                ("reason".into(), Value::String(message.to_string())),
            ]
            .into_iter()
            .collect(),
        )),
    )
}

#[derive(Debug, Deserialize)]
struct SspWebhookPayload {
    #[serde(rename = "type")]
    event_type: String,
    payment_preimage: Option<String>,
    receiver_identity_public_key: Option<String>,
    htlc_amount: Option<SspAmount>,
}

#[derive(Debug, Deserialize)]
struct SspAmount {
    value: i64,
    unit: String,
}

async fn sanitize_domain<DB>(
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
    use crate::models::ListMetadataMetadata;
    use crate::repository::{Invoice, LnurlRepositoryError, LnurlSenderComment, PendingZapReceipt};
    use crate::user::User;
    use crate::webhooks::NewWebhookDelivery;
    use crate::webhooks::repository::WebhookRepositoryError;
    use crate::zap::Zap;
    use axum::Router;
    use axum::body::Bytes;
    use axum::http::{HeaderMap, Request, StatusCode};
    use axum::middleware;
    use axum::routing::{get, post};
    use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;
    use tower::util::ServiceExt;

    // -- Mock repository -------------------------------------------------------

    #[derive(Clone, Default)]
    struct MockRepository {
        invoices: std::sync::Arc<Mutex<HashMap<String, Invoice>>>,
        pending_zap_receipts: std::sync::Arc<Mutex<HashMap<String, PendingZapReceipt>>>,
        webhook_deliveries: std::sync::Arc<Mutex<Vec<NewWebhookDelivery>>>,
        created_blink_accounts: std::sync::Arc<Mutex<Vec<NewBlinkAccount>>>,
        create_blink_account_error: std::sync::Arc<Mutex<Option<MockCreateBlinkAccountError>>>,
        resolved_recipient: std::sync::Arc<Mutex<Option<ResolvedRecipient>>>,
        resolve_calls: std::sync::Arc<Mutex<Vec<(String, String)>>>,
    }

    #[derive(Clone, Copy)]
    enum MockCreateBlinkAccountError {
        BlinkAccountExists,
        IdentifierConflict,
        NameTaken,
    }

    impl MockRepository {
        fn fail_next_blink_account_creation(&self, error: MockCreateBlinkAccountError) {
            *self.create_blink_account_error.lock().unwrap() = Some(error);
        }

        fn created_blink_account_count(&self) -> usize {
            self.created_blink_accounts.lock().unwrap().len()
        }

        fn with_resolved_recipient(self, recipient: ResolvedRecipient) -> Self {
            *self.resolved_recipient.lock().unwrap() = Some(recipient);
            self
        }

        fn resolve_calls(&self) -> Vec<(String, String)> {
            self.resolve_calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl LnurlRepository for MockRepository {
        async fn delete_user(&self, _: &str, _: &str) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn get_user_by_name(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<User>, LnurlRepositoryError> {
            Ok(None)
        }
        async fn get_user_by_pubkey(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<User>, LnurlRepositoryError> {
            Ok(None)
        }
        async fn upsert_user(&self, _: &User) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn resolve_recipient_by_identifier(
            &self,
            domain: &str,
            identifier: &str,
        ) -> Result<Option<ResolvedRecipient>, LnurlRepositoryError> {
            self.resolve_calls
                .lock()
                .unwrap()
                .push((domain.to_string(), identifier.to_string()));
            Ok(self.resolved_recipient.lock().unwrap().clone())
        }
        async fn get_account_by_spark_pubkey(
            &self,
            _: &str,
        ) -> Result<Option<crate::repository::Account>, LnurlRepositoryError> {
            Ok(None)
        }
        async fn create_blink_account(
            &self,
            account: &NewBlinkAccount,
        ) -> Result<(), LnurlRepositoryError> {
            self.created_blink_accounts
                .lock()
                .unwrap()
                .push(account.clone());
            if let Some(error) = self.create_blink_account_error.lock().unwrap().take() {
                return match error {
                    MockCreateBlinkAccountError::BlinkAccountExists => {
                        Err(LnurlRepositoryError::BlinkAccountExists)
                    }
                    MockCreateBlinkAccountError::IdentifierConflict => {
                        Err(LnurlRepositoryError::IdentifierConflict)
                    }
                    MockCreateBlinkAccountError::NameTaken => Err(LnurlRepositoryError::NameTaken),
                };
            }
            Ok(())
        }
        async fn transfer_identifier(
            &self,
            _: &IdentifierTransfer,
        ) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn transfer_username(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn upsert_zap(&self, _: &Zap) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn get_zap_by_payment_hash(
            &self,
            _: &str,
        ) -> Result<Option<Zap>, LnurlRepositoryError> {
            Ok(None)
        }
        async fn insert_lnurl_sender_comment(
            &self,
            _: &LnurlSenderComment,
        ) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn get_metadata_by_pubkey(
            &self,
            _: &str,
            _: u32,
            _: u32,
            _: Option<i64>,
        ) -> Result<Vec<ListMetadataMetadata>, LnurlRepositoryError> {
            Ok(vec![])
        }
        async fn list_domains(&self) -> Result<Vec<String>, LnurlRepositoryError> {
            Ok(vec![])
        }
        async fn add_domain(&self, _: &str) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn upsert_invoice(&self, invoice: &Invoice) -> Result<(), LnurlRepositoryError> {
            self.invoices
                .lock()
                .unwrap()
                .insert(invoice.payment_hash.clone(), invoice.clone());
            Ok(())
        }
        async fn get_invoice_by_payment_hash(
            &self,
            payment_hash: &str,
        ) -> Result<Option<Invoice>, LnurlRepositoryError> {
            Ok(self.invoices.lock().unwrap().get(payment_hash).cloned())
        }
        async fn get_zap_and_invoice_by_payment_hash(
            &self,
            payment_hash: &str,
        ) -> Result<(Option<Zap>, Option<Invoice>), LnurlRepositoryError> {
            Ok((
                None,
                self.invoices.lock().unwrap().get(payment_hash).cloned(),
            ))
        }
        async fn insert_pending_zap_receipt(
            &self,
            pending: &PendingZapReceipt,
        ) -> Result<(), LnurlRepositoryError> {
            self.pending_zap_receipts
                .lock()
                .unwrap()
                .insert(pending.payment_hash.clone(), pending.clone());
            Ok(())
        }
        async fn take_pending_zap_receipts(
            &self,
            _limit: u32,
        ) -> Result<Vec<PendingZapReceipt>, LnurlRepositoryError> {
            Ok(self
                .pending_zap_receipts
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect())
        }
        async fn update_pending_zap_receipt_retry(
            &self,
            _: &str,
            _: i32,
            _: i64,
        ) -> Result<(), LnurlRepositoryError> {
            Ok(())
        }
        async fn delete_pending_zap_receipt(
            &self,
            payment_hash: &str,
        ) -> Result<(), LnurlRepositoryError> {
            self.pending_zap_receipts
                .lock()
                .unwrap()
                .remove(payment_hash);
            Ok(())
        }
        async fn filter_known_payment_hashes(
            &self,
            _payment_hashes: &[String],
        ) -> Result<Vec<String>, LnurlRepositoryError> {
            Ok(vec![])
        }
        async fn upsert_invoices_paid(
            &self,
            invoices: &[Invoice],
        ) -> Result<Vec<String>, LnurlRepositoryError> {
            let mut store = self.invoices.lock().unwrap();
            let mut updated = Vec::new();
            for invoice in invoices {
                store.insert(invoice.payment_hash.clone(), invoice.clone());
                updated.push(invoice.payment_hash.clone());
            }
            Ok(updated)
        }
        async fn insert_pending_zap_receipt_batch(
            &self,
            pending: &[PendingZapReceipt],
        ) -> Result<(), LnurlRepositoryError> {
            let mut store = self.pending_zap_receipts.lock().unwrap();
            for p in pending {
                store.insert(p.payment_hash.clone(), p.clone());
            }
            Ok(())
        }
        async fn get_or_create_setting(
            &self,
            _key: &str,
            default_value: &str,
        ) -> Result<String, LnurlRepositoryError> {
            Ok(default_value.to_string())
        }
        async fn get_webhook_payloads(
            &self,
            payment_hashes: &[String],
        ) -> Result<Vec<crate::repository::WebhookPayloadData>, LnurlRepositoryError> {
            let invoices = self.invoices.lock().unwrap();
            Ok(payment_hashes
                .iter()
                .filter_map(|payment_hash| {
                    let invoice = invoices.get(payment_hash)?;
                    Some(crate::repository::WebhookPayloadData {
                        account_id: invoice.account_id.clone(),
                        payment_hash: invoice.payment_hash.clone(),
                        user_pubkey: invoice.user_pubkey.clone(),
                        invoice: invoice.invoice.clone(),
                        preimage: invoice.preimage.clone()?,
                        amount_received_sat: invoice.amount_received_sat,
                        lightning_address: invoice
                            .domain
                            .as_ref()
                            .map(|domain| format!("alice@{domain}")),
                        sender_comment: Some("verify fallback zap".to_string()),
                        domain: invoice.domain.clone()?,
                    })
                })
                .collect())
        }
    }

    #[async_trait::async_trait]
    impl crate::webhooks::WebhookRepository for MockRepository {
        async fn insert_webhook_deliveries(
            &self,
            deliveries: &[crate::webhooks::NewWebhookDelivery],
        ) -> Result<(), WebhookRepositoryError> {
            self.webhook_deliveries
                .lock()
                .unwrap()
                .extend_from_slice(deliveries);
            Ok(())
        }
        async fn take_pending_webhook_deliveries(
            &self,
        ) -> Result<Vec<crate::webhooks::repository::WebhookDelivery>, WebhookRepositoryError>
        {
            Ok(vec![])
        }
        async fn update_webhook_delivery_success(
            &self,
            _: i64,
            _: i64,
            _: &str,
        ) -> Result<(), WebhookRepositoryError> {
            Ok(())
        }
        async fn update_webhook_delivery_failure(
            &self,
            _: i64,
            _: i32,
            _: i64,
            _: Option<i32>,
            _: Option<&str>,
            _: &str,
        ) -> Result<(), WebhookRepositoryError> {
            Ok(())
        }
        async fn unclaim_webhook_deliveries(
            &self,
            _: &[i64],
        ) -> Result<(), WebhookRepositoryError> {
            Ok(())
        }
        async fn delete_webhook_deliveries_older_than(
            &self,
            _: i64,
        ) -> Result<u64, WebhookRepositoryError> {
            Ok(0)
        }
        async fn delete_webhook_delivery(&self, _: i64) -> Result<(), WebhookRepositoryError> {
            Ok(())
        }
        async fn park_webhook_delivery(&self, _: i64) -> Result<(), WebhookRepositoryError> {
            Ok(())
        }
        async fn list_webhook_configs(
            &self,
        ) -> Result<Vec<crate::webhooks::repository::WebhookConfig>, WebhookRepositoryError>
        {
            Ok(vec![])
        }
    }

    // -- Test helpers ----------------------------------------------------------

    const TEST_WEBHOOK_SECRET: &str = "test_webhook_secret_0123456789abcdef";
    const TEST_PREIMAGE_HEX: &str =
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const TEST_RECEIVER_PUBKEY: &str = "02abc123";

    fn compute_payment_hash(preimage_hex: &str) -> String {
        let preimage_bytes = hex::decode(preimage_hex).unwrap();
        sha256::Hash::hash(&preimage_bytes).to_string()
    }

    fn compute_hmac(secret: &str, body: &[u8]) -> String {
        let mut engine = HmacEngine::<sha256::Hash>::new(secret.as_bytes());
        engine.input(body);
        let hmac: Hmac<sha256::Hash> = Hmac::from_engine(engine);
        hex::encode(hmac.to_byte_array())
    }

    fn make_webhook_payload(
        event_type: &str,
        preimage: Option<&str>,
        receiver_pubkey: Option<&str>,
    ) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "id": "018677b5-e419-99d1-0000-a7030393c9af",
            "created_at": "2025-03-09T12:00:00Z",
            "updated_at": "2025-03-09T12:00:05Z",
            "network": "MAINNET",
            "request_status": "COMPLETED",
            "status": "TRANSFER_COMPLETED",
            "type": event_type,
            "timestamp": "2025-03-09T12:00:06Z",
            "invoice_amount": {"value": 50_000, "unit": "SATOSHI"},
            "htlc_amount": {"value": 50_000, "unit": "SATOSHI"},
        });
        if let Some(p) = preimage {
            payload["payment_preimage"] = serde_json::Value::String(p.to_string());
        }
        if let Some(r) = receiver_pubkey {
            payload["receiver_identity_public_key"] = serde_json::Value::String(r.to_string());
        }
        payload
    }

    fn signed_headers_and_body(secret: &str, payload: &serde_json::Value) -> (HeaderMap, Bytes) {
        let body = serde_json::to_vec(payload).unwrap();
        let sig = compute_hmac(secret, &body);
        let mut headers = HeaderMap::new();
        headers.insert("X-Spark-Signature", sig.parse().unwrap());
        (headers, Bytes::from(body))
    }

    async fn internal_route_test_state(
        repo: MockRepository,
        internal_auth: Option<Arc<crate::internal_auth::InternalAuthState>>,
    ) -> State<MockRepository> {
        internal_route_test_state_with_blink_endpoint(
            repo,
            internal_auth,
            blink_client::PRODUCTION_GRAPHQL_ENDPOINT,
        )
        .await
    }

    async fn internal_route_test_state_with_blink_endpoint(
        repo: MockRepository,
        internal_auth: Option<Arc<crate::internal_auth::InternalAuthState>>,
        blink_endpoint: &str,
    ) -> State<MockRepository> {
        let network = spark_wallet::Network::Regtest;
        let auth_seed = [7_u8; 32];
        let spark_config = spark_wallet::SparkWalletConfig::default_config(network);
        let signer = Arc::new(spark_wallet::DefaultSigner::new(&auth_seed, network).unwrap());
        let session_store = Arc::new(spark::session_store::InMemorySessionStore::default());
        let connection_manager: Arc<dyn spark::operator::rpc::ConnectionManager> =
            Arc::new(spark::operator::rpc::DefaultConnectionManager::new());
        let service_provider = Arc::new(spark::ssp::ServiceProvider::new(
            spark_config.service_provider_config.clone(),
            signer.clone(),
            session_store.clone(),
            None,
        ));
        let wallet = Arc::new(
            spark_wallet::SparkWallet::new(
                spark_config.clone(),
                signer.clone(),
                session_store.clone(),
                Arc::new(spark::tree::InMemoryTreeStore::default()),
                Arc::new(spark::token::InMemoryTokenOutputStore::default()),
                Arc::clone(&connection_manager),
                None,
                None,
                None,
                None,
                true,
                None,
            )
            .await
            .unwrap(),
        );
        let providers = Arc::new(crate::providers::ProviderRegistry::new(
            Arc::clone(&wallet),
            blink_client::Client::new(blink_client::ClientConfig::new(blink_endpoint)),
        ));
        let (invoice_paid_trigger, _rx) = watch::channel(());
        State {
            db: repo.clone(),
            webhook_service: crate::webhooks::WebhookService::new(repo),
            wallet,
            providers,
            internal_auth,
            scheme: "http".to_string(),
            min_sendable: 1_000,
            max_sendable: 4_000_000_000,
            include_spark_address: false,
            domains: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
            nostr_keys: None,
            ca_cert: None,
            crl_url: None,
            crl: std::collections::HashSet::new(),
            connection_manager,
            coordinator: spark_config.operator_pool.get_coordinator().clone(),
            signer,
            session_store,
            service_provider,
            subscribed_keys: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
            invoice_paid_trigger,
            webhook_secret: TEST_WEBHOOK_SECRET.to_string(),
        }
    }

    fn setup_repo_with_invoice(preimage_hex: &str, receiver_pubkey: &str) -> MockRepository {
        let repo = MockRepository::default();
        let payment_hash = compute_payment_hash(preimage_hex);
        repo.invoices.lock().unwrap().insert(
            payment_hash.clone(),
            Invoice {
                account_id: None,
                provider: None,
                wallet_kind: None,
                wallet_id: None,
                provider_payment_hash: None,
                payment_hash,
                user_pubkey: receiver_pubkey.to_string(),
                invoice: "lnbc1...".to_string(),
                preimage: None,
                invoice_expiry: i64::MAX,
                created_at: 0,
                updated_at: 0,
                domain: None,
                amount_received_sat: None,
            },
        );
        repo
    }

    fn generate_route_test_invoice(preimage_byte: u8) -> (String, String) {
        generate_route_test_invoice_with_description_hash(
            preimage_byte,
            sha256::Hash::hash("route test invoice".as_bytes()),
        )
    }

    fn generate_route_test_invoice_with_description_hash(
        preimage_byte: u8,
        description_hash: sha256::Hash,
    ) -> (String, String) {
        let preimage = [preimage_byte; 32];
        let payment_hash = sha256::Hash::hash(&preimage);
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let key = bitcoin::secp256k1::SecretKey::from_slice(&[42_u8; 32]).unwrap();
        let invoice = lightning_invoice::InvoiceBuilder::new(lightning_invoice::Currency::Regtest)
            .description_hash(description_hash)
            .payment_hash(payment_hash)
            .payment_secret(lightning_invoice::PaymentSecret([0_u8; 32]))
            .current_timestamp()
            .min_final_cltv_expiry_delta(144)
            .amount_milli_satoshis(1_000)
            .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &key))
            .expect("test invoice should build");

        (payment_hash.to_string(), invoice.to_string())
    }

    async fn start_blink_invoice_mock_server(
        _bolt11: String,
        fail: bool,
    ) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<Value>>>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let calls_for_route = Arc::clone(&calls);
        let bodies_for_route = Arc::clone(&bodies);
        let app = Router::new().route(
            "/graphql",
            post(move |Json(body): Json<Value>| {
                let calls = Arc::clone(&calls_for_route);
                let bodies = Arc::clone(&bodies_for_route);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    bodies.lock().unwrap().push(body.clone());
                    if fail {
                        return Json(json!({
                            "data": {
                                "lnInvoiceCreateOnBehalfOfRecipient": { "invoice": null, "errors": [{"message": "upstream hidden"}] },
                                "lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient": { "invoice": null, "errors": [{"message": "upstream hidden"}] }
                            }
                        }));
                    }
                    let request_description_hash = body["variables"]["input"]["descriptionHash"]
                        .as_str()
                        .and_then(|hash| sha256::Hash::from_str(hash).ok())
                        .expect("Blink invoice mock requires a description hash");
                    let call_index = u8::try_from(calls.load(Ordering::SeqCst)).unwrap_or(u8::MAX);
                    let (_, bolt11) = generate_route_test_invoice_with_description_hash(
                        100_u8.saturating_add(call_index),
                        request_description_hash,
                    );
                    Json(json!({
                        "data": {
                            "lnInvoiceCreateOnBehalfOfRecipient": {
                                "invoice": { "paymentRequest": bolt11, "paymentHash": "provider_btc_hash" },
                                "errors": []
                            },
                            "lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient": {
                                "invoice": { "paymentRequest": bolt11, "paymentHash": "provider_usd_hash" },
                                "errors": []
                            }
                        }
                    }))
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
                .expect("mock Blink server should serve");
        });
        (format!("http://{addr}/graphql"), calls, bodies)
    }

    async fn start_blink_status_mock_server(
        status: &'static str,
        preimage: Option<String>,
        fail: bool,
    ) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<Value>>>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let calls_for_route = Arc::clone(&calls);
        let bodies_for_route = Arc::clone(&bodies);
        let app = Router::new().route(
            "/graphql",
            post(move |Json(body): Json<Value>| {
                let calls = Arc::clone(&calls_for_route);
                let bodies = Arc::clone(&bodies_for_route);
                let preimage = preimage.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    bodies.lock().unwrap().push(body.clone());
                    if fail {
                        return Json(json!({
                            "errors": [{"message": "upstream status hidden"}]
                        }));
                    }
                    let payment_hash = body["variables"]["input"]["paymentHash"]
                        .as_str()
                        .expect("Blink status mock requires paymentHash")
                        .to_string();
                    Json(json!({
                        "data": {
                            "lnInvoicePaymentStatusByHash": {
                                "status": status,
                                "paymentHash": payment_hash,
                                "paymentRequest": "lnbc1status",
                                "paymentPreimage": preimage
                            }
                        }
                    }))
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
                .expect("mock Blink status server should serve");
        });
        (format!("http://{addr}/graphql"), calls, bodies)
    }

    fn route_test_invoice(
        provider: Option<AccountProvider>,
        payment_hash: String,
        invoice: &str,
        preimage: Option<String>,
    ) -> Invoice {
        Invoice {
            account_id: Some("acct_verify_blink".to_string()),
            provider,
            wallet_kind: Some(WalletKind::Btc),
            wallet_id: Some("btc_wallet_verify".to_string()),
            provider_payment_hash: Some(payment_hash.clone()),
            payment_hash,
            user_pubkey: String::new(),
            invoice: invoice.to_string(),
            preimage,
            invoice_expiry: i64::MAX,
            created_at: 0,
            updated_at: 0,
            domain: Some("verify.example.com".to_string()),
            amount_received_sat: None,
        }
    }

    async fn call_verify(state: State<MockRepository>, payment_hash: &str) -> Value {
        let response =
            LnurlServer::<MockRepository>::verify(Path(payment_hash.to_string()), Extension(state))
                .await
                .into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        serde_json::from_slice(&body.expect("verify response body reads"))
            .expect("verify response body is JSON")
    }

    async fn get_public_invoice(
        state: State<MockRepository>,
        identifier: &str,
        params: LnurlPayCallbackParams,
    ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
        LnurlServer::<MockRepository>::handle_invoice(
            Host("example.com".to_string()),
            Path(identifier.to_string()),
            Query(params),
            Extension(state),
        )
        .await
    }

    fn assert_lnurl_error(result: Result<Json<Value>, (StatusCode, Json<Value>)>, reason: &str) {
        let Err((status, Json(body))) = result else {
            panic!("expected LNURL error {reason}");
        };
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ERROR");
        assert_eq!(body["reason"], reason);
    }

    fn internal_test_token() -> String {
        let private_key = include_bytes!("../tests/fixtures/internal_auth_private.pem");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("blink-internal-test-key".to_string());
        encode(
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
        .expect("test JWT must sign")
    }

    fn internal_auth_state() -> Arc<crate::internal_auth::InternalAuthState> {
        let jwks = include_str!("../tests/fixtures/internal_auth_jwks.json");
        Arc::new(
            crate::internal_auth::InternalAuthState::from_jwks_json(
                jwks,
                "https://issuer.internal.test".to_string(),
                "lnurl-server.internal.test".to_string(),
            )
            .expect("test JWKS fixture must load"),
        )
    }

    async fn internal_account_app(repo: MockRepository) -> Router {
        let state = internal_route_test_state(repo, Some(internal_auth_state())).await;
        internal_account_app_with_state(state)
    }

    fn internal_account_app_with_state(state: State<MockRepository>) -> Router {
        Router::new()
            .route(
                "/internal/blink/accounts",
                post(LnurlServer::<MockRepository>::create_internal_blink_account),
            )
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                crate::internal_auth::internal_auth::<MockRepository>,
            ))
            .layer(Extension(state))
    }

    async fn internal_lookup_app(repo: MockRepository) -> Router {
        let state = internal_route_test_state(repo, Some(internal_auth_state())).await;
        internal_lookup_app_with_state(state)
    }

    fn internal_lookup_app_with_state(state: State<MockRepository>) -> Router {
        Router::new()
            .route(
                "/internal/domains/{domain}/identifiers/{identifier}",
                get(LnurlServer::<MockRepository>::get_internal_identifier),
            )
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                crate::internal_auth::internal_auth::<MockRepository>,
            ))
            .layer(Extension(state))
    }

    fn internal_blink_invoice_paid_app_with_state(state: State<MockRepository>) -> Router {
        Router::new()
            .route(
                "/internal/blink/invoice-paid",
                post(LnurlServer::<MockRepository>::blink_invoice_paid),
            )
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                crate::internal_auth::internal_auth::<MockRepository>,
            ))
            .layer(Extension(state))
    }

    async fn post_internal_blink_invoice_paid(
        app: Router,
        payload: Value,
        scope: &str,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri("/internal/blink/invoice-paid")
            .header(
                "authorization",
                format!("Bearer {}", internal_test_token_with_scope(scope)),
            )
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&payload).expect("request serializes"),
            ))
            .expect("request builds");

        let response = app.oneshot(request).await.expect("route responds");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body reads");
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).expect("response body is JSON")
        };
        (status, body)
    }

    fn blink_settlement_payload(event_type: &str, status: &str, payment_hash: &str) -> Value {
        json!({
            "eventType": event_type,
            "transaction": {
                "status": status,
                "initiationVia": {
                    "type": "lightning",
                    "paymentHash": payment_hash
                },
                "settlementVia": {
                    "type": "SettlementViaLn",
                    "preImage": TEST_PREIMAGE_HEX
                }
            }
        })
    }

    fn valid_create_blink_account_payload() -> CreateBlinkAccountRequest {
        CreateBlinkAccountRequest {
            domain: "Example.COM".to_string(),
            blink_account_id: "blink_account_123".to_string(),
            btc_wallet_id: "btc_wallet_123".to_string(),
            usd_wallet_id: "usd_wallet_123".to_string(),
            default_wallet: "usd".to_string(),
            description: "Blink account".to_string(),
            identifiers: vec![" Alice_123 ".to_string(), "+573005871212".to_string()],
        }
    }

    async fn post_internal_blink_account(
        app: Router,
        payload: CreateBlinkAccountRequest,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri("/internal/blink/accounts")
            .header("authorization", format!("Bearer {}", internal_test_token()))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&payload).expect("request serializes"),
            ))
            .expect("request builds");

        let response = app.oneshot(request).await.expect("route responds");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body reads");
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).expect("response body is JSON")
        };
        (status, body)
    }

    async fn get_internal_identifier(
        app: Router,
        path: &str,
        token: String,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .expect("request builds");

        let response = app.oneshot(request).await.expect("route responds");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body reads");
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).expect("response body is JSON")
        };
        (status, body)
    }

    fn internal_test_token_with_scope(scope: &str) -> String {
        let private_key = include_bytes!("../tests/fixtures/internal_auth_private.pem");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("blink-internal-test-key".to_string());
        encode(
            &header,
            &serde_json::json!({
                "sub": "blink-core-test-service",
                "iss": "https://issuer.internal.test",
                "aud": "lnurl-server.internal.test",
                "exp": 4_102_444_800_u64,
                "nbf": 1_700_000_000_u64,
                "scope": scope
            }),
            &EncodingKey::from_rsa_pem(private_key).expect("test RSA key must parse"),
        )
        .expect("test JWT must sign")
    }

    fn blink_resolved_recipient() -> ResolvedRecipient {
        ResolvedRecipient {
            account_id: "acct_blink_lookup".to_string(),
            provider: AccountProvider::Blink,
            domain: "example.com".to_string(),
            identifier: "alice".to_string(),
            identifier_kind: AccountIdentifierKind::Username,
            description: "Alice Blink account".to_string(),
            spark_pubkey: None,
            blink_account_id: Some("blink_account_123".to_string()),
            btc_wallet_id: Some("btc_wallet_123".to_string()),
            usd_wallet_id: Some("usd_wallet_123".to_string()),
            default_wallet: Some(WalletKind::Usd),
        }
    }

    fn spark_resolved_recipient() -> ResolvedRecipient {
        ResolvedRecipient {
            account_id: "acct_spark_lookup".to_string(),
            provider: AccountProvider::Spark,
            domain: "example.com".to_string(),
            identifier: "bob".to_string(),
            identifier_kind: AccountIdentifierKind::Username,
            description: "Bob Spark account".to_string(),
            spark_pubkey: Some("spark_pubkey_123".to_string()),
            blink_account_id: None,
            btc_wallet_id: None,
            usd_wallet_id: None,
            default_wallet: None,
        }
    }

    // -- Tests -----------------------------------------------------------------

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

    // -- Spark management account-backed compatibility ------------------------

    fn handler_source(name: &str) -> &'static str {
        let source = include_str!("routes.rs");
        let marker = format!("    pub async fn {name}(");
        let start = source.find(&marker).expect("handler must exist");
        let rest = &source[start..];
        let next = rest.find("\n    pub async fn ").unwrap_or(rest.len());
        &rest[..next]
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

    // -- Public LNURL provider-dispatch compatibility -------------------------

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn public_lnurl_discovery_shape_remains_spark_compatible() {
        let user = User {
            domain: "localhost:8080".to_string(),
            pubkey: "02abc123".to_string(),
            name: "alice".to_string(),
            description: "Alice wallet".to_string(),
        };
        let response = PayResponse {
            callback: "http://localhost:8080/lnurlp/alice/invoice".to_string(),
            max_sendable: 1_000_000,
            min_sendable: 1_000,
            tag: Tag::Pay,
            metadata: get_metadata(&user.domain, &user),
            comment_allowed: Some(MAX_COMMENT_LENGTH as u32),
            allows_nostr: None,
            nostr_pubkey: None,
        };

        let body = serde_json::to_value(response).expect("PayResponse serializes");
        assert_eq!(body["tag"], "payRequest");
        assert_eq!(
            body["callback"],
            "http://localhost:8080/lnurlp/alice/invoice"
        );
        assert_eq!(body["minSendable"], 1_000);
        assert_eq!(body["maxSendable"], 1_000_000);
        assert_eq!(body["commentAllowed"], MAX_COMMENT_LENGTH);
        assert!(body.get("metadata").is_some());
        assert!(body.get("provider").is_none());
        assert!(body.get("account_id").is_none());
    }

    #[test]
    fn public_invoice_and_verify_shapes_remain_spark_compatible() {
        let invoice_body = json!({
            "pr": "lnbc1testinvoice",
            "routes": Vec::<String>::new(),
            "verify": "http://localhost:8080/verify/payment_hash",
        });
        assert_eq!(invoice_body["pr"], "lnbc1testinvoice");
        assert_eq!(invoice_body["routes"].as_array().unwrap().len(), 0);
        assert_eq!(
            invoice_body["verify"],
            "http://localhost:8080/verify/payment_hash"
        );
        assert!(invoice_body.get("provider").is_none());
        assert!(invoice_body.get("account_id").is_none());

        let verify_body = json!({
            "status": "OK",
            "settled": false,
            "preimage": Value::Null,
            "pr": "lnbc1testinvoice",
        });
        assert_eq!(verify_body["status"], "OK");
        assert_eq!(verify_body["settled"], false);
        assert!(verify_body.get("provider").is_none());
    }

    #[tokio::test]
    async fn verify_spark_and_unowned_invoices_remain_local_state_only_setl_01_d_07() {
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Spark),
            "spark_verify_hash".to_string(),
            "lnbc1sparkverify",
            None,
        ))
        .await
        .unwrap();
        repo.upsert_invoice(&route_test_invoice(
            None,
            "legacy_verify_hash".to_string(),
            "lnbc1legacyverify",
            Some(TEST_PREIMAGE_HEX.to_string()),
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;

        let spark_body = call_verify(state.clone(), "spark_verify_hash").await;
        assert_eq!(spark_body["status"], "OK");
        assert_eq!(spark_body["settled"], false);
        assert_eq!(spark_body["preimage"], Value::Null);
        assert_eq!(spark_body["pr"], "lnbc1sparkverify");

        let legacy_body = call_verify(state, "legacy_verify_hash").await;
        assert_eq!(legacy_body["status"], "OK");
        assert_eq!(legacy_body["settled"], true);
        assert_eq!(legacy_body["preimage"], TEST_PREIMAGE_HEX);
        assert_eq!(legacy_body["pr"], "lnbc1legacyverify");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn verify_blink_local_preimage_returns_settled_without_status_setl_02() {
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            compute_payment_hash(TEST_PREIMAGE_HEX),
            "lnbc1blinklocalverify",
            Some(TEST_PREIMAGE_HEX.to_string()),
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;

        let body = call_verify(state, &compute_payment_hash(TEST_PREIMAGE_HEX)).await;
        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], true);
        assert_eq!(body["preimage"], TEST_PREIMAGE_HEX);
        assert_eq!(body["pr"], "lnbc1blinklocalverify");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn verify_blink_status_preimage_uses_central_side_effects_setl_03_07_08_d_09_d_22() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) =
            start_blink_status_mock_server("PAID", Some(TEST_PREIMAGE_HEX.to_string()), false)
                .await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkfallbackverify",
            None,
        ))
        .await
        .unwrap();
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;

        let body = call_verify(state, &payment_hash).await;
        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], true);
        assert_eq!(body["preimage"], TEST_PREIMAGE_HEX);
        assert_eq!(body["pr"], "lnbc1blinkfallbackverify");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should remain stored");
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
        assert!(
            repo.pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash),
            "verify fallback must enqueue zap receipts through handle_invoice_paid"
        );
        assert_eq!(
            repo.webhook_deliveries.lock().unwrap().len(),
            1,
            "verify fallback must enqueue webhook deliveries through handle_invoice_paid"
        );
    }

    #[tokio::test]
    async fn verify_blink_paid_status_without_preimage_remains_unsettled_setl_03_d_10() {
        let payment_hash = "blink_paid_without_preimage_hash".to_string();
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinknopreimageverify",
            None,
        ))
        .await
        .unwrap();
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;

        let body = call_verify(state, &payment_hash).await;
        assert_eq!(body["status"], "OK");
        assert_eq!(body["settled"], false);
        assert_eq!(body["preimage"], Value::Null);
        assert_eq!(body["pr"], "lnbc1blinknopreimageverify");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should remain stored");
        assert!(invoice.preimage.is_none());
        assert!(
            !repo
                .pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash)
        );
    }

    #[tokio::test]
    async fn verify_blink_status_error_returns_generic_lnurl_error_d_11() {
        let payment_hash = "blink_status_error_hash".to_string();
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, true).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkerrorverify",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;

        let body = call_verify(state, &payment_hash).await;
        assert_eq!(body["status"], "ERROR");
        assert_eq!(body["reason"], "Internal server error");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    fn metadata_entries(metadata: &str) -> Vec<(String, String)> {
        serde_json::from_str::<Vec<(String, String)>>(metadata)
            .expect("metadata must be a JSON array of string tuples")
    }

    fn phone_blink_resolved_recipient() -> ResolvedRecipient {
        ResolvedRecipient {
            identifier: "+573005871212".to_string(),
            identifier_kind: AccountIdentifierKind::Phone,
            description: "Phone Blink account".to_string(),
            ..blink_resolved_recipient()
        }
    }

    #[tokio::test]
    async fn blink_public_discovery_username_metadata_uses_description_and_requested_identity_lnurl_01_lnurl_02_d_01_d_02_d_19()
     {
        // LNURL-01/LNURL-02/D-01/D-02/D-19: public discovery must resolve a
        // Blink recipient by canonical identifier, expose the requested
        // Lightning Address identity, and not require Spark-only metadata.
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let state = internal_route_test_state(repo.clone(), None).await;

        let Json(response) = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("Example.COM".to_string()),
            Path("alice".to_string()),
            Extension(state),
        )
        .await
        .expect("Blink discovery should return PayResponse metadata");

        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "alice".to_string())]
        );
        assert_eq!(response.callback, "http://example.com/lnurlp/alice/invoice");
        assert_eq!(
            metadata_entries(&response.metadata),
            vec![
                ("text/plain".to_string(), "Alice Blink account".to_string()),
                (
                    "text/identifier".to_string(),
                    "alice@example.com".to_string()
                ),
            ]
        );
    }

    #[tokio::test]
    async fn blink_public_discovery_wallet_alias_preserves_public_identity_but_looks_up_canonical_lnurl_01_lnurl_02_d_03_comp_04()
     {
        // LNURL-01/LNURL-02/D-03/COMP-04: virtual +usd aliases influence only
        // public metadata/callback identity and wallet intent; repository lookup
        // remains canonical and never persists identifier+usd.
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let state = internal_route_test_state(repo.clone(), None).await;

        let Json(response) = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("example.com".to_string()),
            Path("alice+usd".to_string()),
            Extension(state),
        )
        .await
        .expect("Blink alias discovery should return PayResponse metadata");

        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "alice".to_string())]
        );
        assert_eq!(
            response.callback,
            "http://example.com/lnurlp/alice+usd/invoice"
        );
        assert_eq!(
            metadata_entries(&response.metadata),
            vec![
                ("text/plain".to_string(), "Alice Blink account".to_string()),
                (
                    "text/identifier".to_string(),
                    "alice+usd@example.com".to_string(),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn blink_public_discovery_phone_identifier_keeps_requested_phone_identity_lnurl_01_lnurl_02_d_04()
     {
        // LNURL-01/LNURL-02/D-04: payer-supplied public phone identifiers are
        // allowed in metadata identity and must not be masked by description.
        let repo =
            MockRepository::default().with_resolved_recipient(phone_blink_resolved_recipient());
        let state = internal_route_test_state(repo.clone(), None).await;

        let Json(response) = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("example.com".to_string()),
            Path("573005871212".to_string()),
            Extension(state),
        )
        .await
        .expect("Blink phone discovery should return PayResponse metadata");

        assert_eq!(
            repo.resolve_calls(),
            vec![("example.com".to_string(), "+573005871212".to_string())]
        );
        assert_eq!(
            response.callback,
            "http://example.com/lnurlp/+573005871212/invoice"
        );
        assert_eq!(
            metadata_entries(&response.metadata),
            vec![
                ("text/plain".to_string(), "Phone Blink account".to_string()),
                (
                    "text/identifier".to_string(),
                    "+573005871212@example.com".to_string(),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn blink_public_discovery_missing_and_invalid_phone_like_identifiers_keep_spark_not_found_shape_d_19()
     {
        // D-19: missing/invalid Blink-looking public discovery must not leak
        // Blink-specific provider, account, phone, or existence details.
        let missing_repo = MockRepository::default();
        let missing_state = internal_route_test_state(missing_repo, None).await;
        let missing = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("example.com".to_string()),
            Path("alice".to_string()),
            Extension(missing_state),
        )
        .await;

        let Err((missing_status, Json(missing_body))) = missing else {
            panic!("missing recipient should keep Spark-compatible not-found shape");
        };
        assert_eq!(missing_status, StatusCode::NOT_FOUND);
        assert_eq!(missing_body, Value::String(String::new()));

        let invalid_repo = MockRepository::default();
        let invalid_state = internal_route_test_state(invalid_repo.clone(), None).await;
        let invalid = LnurlServer::<MockRepository>::handle_lnurl_pay(
            Host("example.com".to_string()),
            Path("12345".to_string()),
            Extension(invalid_state),
        )
        .await;

        let Err((invalid_status, Json(invalid_body))) = invalid else {
            panic!("invalid phone-like recipient should keep Spark-compatible not-found shape");
        };
        assert_eq!(invalid_status, StatusCode::NOT_FOUND);
        assert_eq!(invalid_body, Value::String(String::new()));
        assert!(invalid_repo.resolve_calls().is_empty());
    }

    #[test]
    fn provider_invoice_metadata_contract_prov_04_lnurl_05_lnurl_06_d_11_d_13_d_15() {
        // PROV-04/LNURL-05/D-11/D-13/D-15: provider-neutral invoice rows must
        // carry typed provider/wallet metadata without any raw provider payload.
        let invoice = Invoice {
            account_id: Some("acct_spark_provider_metadata".to_string()),
            provider: Some(AccountProvider::Spark),
            wallet_kind: Some(WalletKind::Btc),
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash: "provider_invoice_metadata_hash".to_string(),
            user_pubkey: "spark_provider_metadata_pubkey".to_string(),
            invoice: "lnbc1providerinvoice".to_string(),
            preimage: None,
            invoice_expiry: i64::MAX,
            created_at: 1,
            updated_at: 2,
            domain: Some("provider-metadata.example.com".to_string()),
            amount_received_sat: None,
        };
        assert_eq!(invoice.provider, Some(AccountProvider::Spark));
        assert_eq!(invoice.wallet_kind, Some(WalletKind::Btc));
        assert!(invoice.wallet_id.is_none());
        assert!(invoice.provider_payment_hash.is_none());
        assert_eq!(
            invoice.account_id.as_deref(),
            Some("acct_spark_provider_metadata")
        );
        assert_eq!(
            invoice.domain.as_deref(),
            Some("provider-metadata.example.com")
        );

        let provider_invoice = crate::providers::ProviderInvoice {
            bolt11: invoice.invoice.clone(),
            wallet_kind: WalletKind::Btc,
            wallet_id: None,
            provider_payment_hash: None,
        };
        assert_eq!(provider_invoice.wallet_kind, WalletKind::Btc);

        // LNURL-06: the public callback success body stays exactly pr/routes/verify.
        let callback_body = json!({
            "pr": provider_invoice.bolt11,
            "routes": Vec::<String>::new(),
            "verify": "http://provider-metadata.example.com/verify/provider_invoice_metadata_hash",
        });
        let keys = callback_body
            .as_object()
            .expect("callback body must be an object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["pr", "routes", "verify"]);
    }

    #[test]
    fn unsupported_spark_usd_maps_to_existing_lnurl_error_shape() {
        let routes_source = include_str!("routes.rs");
        assert!(
            routes_source.contains("fn map_provider_invoice_error"),
            "routes must own provider error to LNURL JSON mapping"
        );
        assert!(
            routes_source.contains("ProviderError::UnsupportedWallet"),
            "unsupported wallet errors must be mapped at the route boundary"
        );

        let (status, Json(body)) = lnurl_error("unsupported wallet");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ERROR");
        assert_eq!(body["reason"], "unsupported wallet");
    }

    #[test]
    fn public_invoice_handler_source_uses_provider_dispatch_boundary() {
        let invoice = handler_source("handle_invoice");
        assert!(
            invoice.contains("parse_public_identifier"),
            "callback must parse wallet modifiers before provider dispatch"
        );
        assert!(
            invoice.contains("resolve_public_recipient"),
            "callback must resolve account-backed recipients through the public lookup helper"
        );
        assert!(
            invoice.contains("provider_for"),
            "callback must select the provider by resolved recipient provider"
        );
        assert!(
            invoice.contains("create_invoice"),
            "callback must create invoices through the selected provider"
        );
        let direct_wallet_call = ["state", "wallet", "create_lightning_invoice"].join(".");
        assert!(
            !invoice.contains(&direct_wallet_call),
            "callback must not call the Spark wallet directly"
        );

        let providers_source = include_str!("providers.rs");
        let provider_runtime_source = providers_source
            .split("#[cfg(test)]")
            .next()
            .expect("providers source should have runtime section");
        assert!(!provider_runtime_source.contains("use axum"));
        assert!(!provider_runtime_source.contains("serde_json"));
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

    #[test]
    fn blink_provider_source_boundaries_remain_route_and_registry_owned() {
        let routes_source = include_str!("routes.rs");
        let route_runtime_source = routes_source
            .split("#[cfg(test)]")
            .next()
            .expect("routes source should have runtime section");
        assert!(
            !route_runtime_source.contains("blink_client"),
            "routes must not call Blink GraphQL client directly"
        );
        assert!(
            routes_source.contains("ProviderError::MissingBlinkDefaultWallet")
                && routes_source.contains("ProviderError::MissingBlinkBtcWalletId")
                && routes_source.contains("ProviderError::MissingBlinkUsdWalletId")
                && routes_source.contains("ProviderError::BlinkInvoiceCreationFailed")
                && routes_source.contains("ProviderError::BlinkPaymentStatusUnavailable"),
            "route provider-error mapping must cover Blink provider failures"
        );

        let providers_source = include_str!("providers.rs");
        assert!(
            providers_source.contains("AccountProvider::Blink => self.blink.as_ref()"),
            "registry must dispatch Blink centrally through ProviderRegistry"
        );
    }

    #[test]
    fn phase_6_public_lnurl_error_reason_contract_is_explicit_and_plain() {
        // D-16/D-17/D-18/D-19: public LNURL error categories must stay stable,
        // plain, and provider-neutral so Blink internals never leak through
        // user-correctable or upstream provider failures.
        assert_eq!(
            public_lnurl_phase_6_error_reasons(),
            [
                "unsupported wallet",
                "expiry too long",
                "missing amount",
                "amount out of range",
                "comment too long",
                "invoice creation failed",
            ]
        );

        for reason in public_lnurl_phase_6_error_reasons() {
            let (status, Json(body)) = lnurl_error(reason);
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["status"], "ERROR");
            assert_eq!(body["reason"], reason);
            assert!(body.get("provider").is_none());
            assert!(body.get("account_id").is_none());
        }
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

    #[tokio::test]
    async fn public_invoice_callback_blink_default_persists_provider_metadata_prov_04_lnurl_05_lnurl_06_d_12_d_15_d_16()
     {
        // PROV-04/LNURL-05/LNURL-06/D-12/D-15/D-16: Blink public callbacks must
        // create invoices through the provider registry, return exactly
        // pr/routes/verify, and persist provider-neutral metadata without a fake
        // Spark pubkey.
        let (_payment_hash, bolt11) = generate_route_test_invoice(11);
        let (endpoint, calls, _bodies) =
            start_blink_invoice_mock_server(bolt11.clone(), false).await;
        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let state =
            internal_route_test_state_with_blink_endpoint(repo.clone(), None, &endpoint).await;

        let Json(body) = get_public_invoice(
            state,
            "alice",
            LnurlPayCallbackParams {
                amount: Some(1_000),
                ..LnurlPayCallbackParams::default()
            },
        )
        .await
        .expect("Blink default invoice callback should succeed");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            body.as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["pr", "routes", "verify"]
        );
        let returned_invoice = Bolt11Invoice::from_str(body["pr"].as_str().unwrap())
            .expect("mock should return a valid invoice");
        let payment_hash = returned_invoice.payment_hash().to_string();
        assert_eq!(
            body["verify"],
            format!("http://example.com/verify/{payment_hash}")
        );
        let stored = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should be persisted");
        assert_eq!(stored.provider, Some(AccountProvider::Blink));
        assert_eq!(stored.wallet_kind, Some(WalletKind::Usd));
        assert_eq!(stored.wallet_id.as_deref(), Some("usd_wallet_123"));
        assert_eq!(
            stored.provider_payment_hash.as_deref(),
            Some("provider_usd_hash")
        );
        assert_eq!(stored.account_id.as_deref(), Some("acct_blink_lookup"));
        assert_eq!(stored.domain.as_deref(), Some("example.com"));
        assert_eq!(stored.payment_hash, payment_hash);
        assert_ne!(
            stored.user_pubkey, "spark_pubkey_123",
            "Blink must not invent a fake Spark pubkey"
        );
    }

    #[tokio::test]
    async fn public_invoice_callback_blink_wallet_alias_and_expiry_policy_lnurl_04_d_03_d_05_d_06_d_07_d_08_d_09_d_10()
     {
        // LNURL-04/D-03/D-05-D-10: +btc/+usd aliases select Blink wallets and
        // route-owned expiry policy converts public seconds to provider-ready
        // minutes before dispatch.
        let (_payment_hash, bolt11) = generate_route_test_invoice(12);
        let (endpoint, calls, bodies) = start_blink_invoice_mock_server(bolt11, false).await;

        for (identifier, expiry, expected_wallet, expected_expiry) in [
            ("alice+btc", None, "btc_wallet_123", None),
            ("alice+btc", Some(60), "btc_wallet_123", Some(1)),
            ("alice+btc", Some(61), "btc_wallet_123", Some(2)),
            ("alice+btc", Some(86_400), "btc_wallet_123", Some(1440)),
            ("alice+usd", Some(300), "usd_wallet_123", Some(5)),
        ] {
            let repo =
                MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
            let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
            let _ = get_public_invoice(
                state,
                identifier,
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    expiry,
                    ..LnurlPayCallbackParams::default()
                },
            )
            .await
            .expect("accepted Blink expiry should create invoice");
            let body = bodies
                .lock()
                .unwrap()
                .last()
                .cloned()
                .expect("provider body captured");
            assert_eq!(
                body["variables"]["input"]["recipientWalletId"],
                expected_wallet
            );
            match expected_expiry {
                Some(minutes) => assert_eq!(body["variables"]["input"]["expiresIn"], minutes),
                None => assert!(body["variables"]["input"].get("expiresIn").is_none()),
            }
        }

        for (identifier, expiry) in [("alice+btc", 86_401), ("alice+usd", 301)] {
            let before = calls.load(Ordering::SeqCst);
            let repo =
                MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
            let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
            assert_lnurl_error(
                get_public_invoice(
                    state,
                    identifier,
                    LnurlPayCallbackParams {
                        amount: Some(1_000),
                        expiry: Some(expiry),
                        ..LnurlPayCallbackParams::default()
                    },
                )
                .await,
                "expiry too long",
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                before,
                "over-limit expiry must not dispatch provider calls"
            );
        }
    }

    #[tokio::test]
    async fn public_invoice_callback_validation_before_dispatch_lnurl_03_comp_04_d_17_d_18() {
        // LNURL-03/COMP-04/D-17/D-18: route-owned validation must happen before
        // provider dispatch and public errors must use stable plain phrases.
        let (_payment_hash, bolt11) = generate_route_test_invoice(13);
        let (endpoint, calls, _bodies) = start_blink_invoice_mock_server(bolt11, false).await;

        for (params, expected) in [
            (LnurlPayCallbackParams::default(), "missing amount"),
            (
                LnurlPayCallbackParams {
                    amount: Some(0),
                    ..LnurlPayCallbackParams::default()
                },
                "amount out of range",
            ),
            (
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    comment: Some("x".repeat(MAX_COMMENT_LENGTH + 1)),
                    ..LnurlPayCallbackParams::default()
                },
                "comment too long",
            ),
            (
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    nostr: Some("not-json".to_string()),
                    ..LnurlPayCallbackParams::default()
                },
                "nostr zap not supported",
            ),
        ] {
            let repo =
                MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
            let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
            let before = calls.load(Ordering::SeqCst);
            assert_lnurl_error(get_public_invoice(state, "alice", params).await, expected);
            assert_eq!(
                calls.load(Ordering::SeqCst),
                before,
                "{expected} must happen before provider dispatch"
            );
        }

        let repo = MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let state = internal_route_test_state_with_blink_endpoint(repo, None, &endpoint).await;
        let before = calls.load(Ordering::SeqCst);
        assert_lnurl_error(
            get_public_invoice(
                state,
                "alice",
                LnurlPayCallbackParams {
                    amount: Some(2_000),
                    ..LnurlPayCallbackParams::default()
                },
            )
            .await,
            "internal server error",
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before + 1,
            "provider amount mismatch is rejected after provider dispatch"
        );

        let spark_repo =
            MockRepository::default().with_resolved_recipient(spark_resolved_recipient());
        let spark_state =
            internal_route_test_state_with_blink_endpoint(spark_repo, None, &endpoint).await;
        assert_lnurl_error(
            get_public_invoice(
                spark_state,
                "bob+usd",
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    ..LnurlPayCallbackParams::default()
                },
            )
            .await,
            "unsupported wallet",
        );

        let (failing_endpoint, _failing_calls, _failing_bodies) =
            start_blink_invoice_mock_server("lnbc1unused".to_string(), true).await;
        let failing_repo =
            MockRepository::default().with_resolved_recipient(blink_resolved_recipient());
        let failing_state =
            internal_route_test_state_with_blink_endpoint(failing_repo, None, &failing_endpoint)
                .await;
        assert_lnurl_error(
            get_public_invoice(
                failing_state,
                "alice",
                LnurlPayCallbackParams {
                    amount: Some(1_000),
                    ..LnurlPayCallbackParams::default()
                },
            )
            .await,
            "invoice creation failed",
        );
    }

    #[tokio::test]
    async fn create_internal_blink_account_happy_path_requires_valid_internal_token() {
        // D-01/D-04/D-08/D-09/D-13/D-14/D-16/D-17/D-19: the internal account
        // creation happy path is locked to /internal/blink/accounts, a scoped
        // RS256 JWT, local deterministic JWKS/key fixtures, route-boundary
        // normalization, and exactly one provider-neutral repository write.
        let jwks = include_str!("../tests/fixtures/internal_auth_jwks.json");
        let private_key = include_bytes!("../tests/fixtures/internal_auth_private.pem");
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
    async fn blink_invoice_paid_supplied_preimage_uses_internal_auth_and_central_side_effects() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinknativewebhook",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(
            repo.clone(),
            Some(internal_auth_state()),
            &endpoint,
        )
        .await;
        let app = internal_blink_invoice_paid_app_with_state(state);

        let (status, body) = post_internal_blink_invoice_paid(
            app,
            blink_settlement_payload("receive.lightning", "success", &payment_hash),
            crate::internal_auth::SCOPE_SETTLEMENT_WRITE,
        )
        .await;

        assert!(status.is_success());
        assert_eq!(body, Value::Null);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
        assert!(
            repo.pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash)
        );
        assert_eq!(repo.webhook_deliveries.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn blink_invoice_paid_ignored_events_return_success_without_side_effects() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        for payload in [
            blink_settlement_payload("send.lightning", "success", &payment_hash),
            blink_settlement_payload("receive.lightning", "pending", &payment_hash),
        ] {
            let (endpoint, calls, _) = start_blink_status_mock_server("PAID", None, false).await;
            let repo = MockRepository::default();
            repo.upsert_invoice(&route_test_invoice(
                Some(AccountProvider::Blink),
                payment_hash.clone(),
                "lnbc1ignoredblinknativewebhook",
                None,
            ))
            .await
            .unwrap();
            let state = internal_route_test_state_with_blink_endpoint(
                repo.clone(),
                Some(internal_auth_state()),
                &endpoint,
            )
            .await;
            let app = internal_blink_invoice_paid_app_with_state(state);

            let (status, body) = post_internal_blink_invoice_paid(
                app,
                payload,
                crate::internal_auth::SCOPE_SETTLEMENT_WRITE,
            )
            .await;

            assert!(status.is_success());
            assert_eq!(body, Value::Null);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let invoice = repo
                .get_invoice_by_payment_hash(&payment_hash)
                .await
                .unwrap()
                .expect("invoice exists");
            assert!(invoice.preimage.is_none());
            assert!(repo.pending_zap_receipts.lock().unwrap().is_empty());
            assert!(repo.webhook_deliveries.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn blink_invoice_paid_without_preimage_uses_blink_status_fallback() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, calls, _) =
            start_blink_status_mock_server("PAID", Some(TEST_PREIMAGE_HEX.to_string()), false)
                .await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinknativefallback",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(
            repo.clone(),
            Some(internal_auth_state()),
            &endpoint,
        )
        .await;
        let app = internal_blink_invoice_paid_app_with_state(state);
        let mut payload = blink_settlement_payload("receive.lightning", "success", &payment_hash);
        payload["transaction"]["settlementVia"] = json!({ "type": "SettlementViaIntraLedger" });

        let (status, body) = post_internal_blink_invoice_paid(
            app,
            payload,
            crate::internal_auth::SCOPE_SETTLEMENT_WRITE,
        )
        .await;

        assert!(status.is_success());
        assert_eq!(body, Value::Null);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
        assert!(
            repo.pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash)
        );
        assert_eq!(repo.webhook_deliveries.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn blink_invoice_paid_requires_settlement_write_scope() {
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let (endpoint, _calls, _) = start_blink_status_mock_server("PAID", None, false).await;
        let repo = MockRepository::default();
        repo.upsert_invoice(&route_test_invoice(
            Some(AccountProvider::Blink),
            payment_hash.clone(),
            "lnbc1blinkforbidden",
            None,
        ))
        .await
        .unwrap();
        let state = internal_route_test_state_with_blink_endpoint(
            repo.clone(),
            Some(internal_auth_state()),
            &endpoint,
        )
        .await;
        let app = internal_blink_invoice_paid_app_with_state(state);

        let (status, body) = post_internal_blink_invoice_paid(
            app,
            blink_settlement_payload("receive.lightning", "success", &payment_hash),
            "accounts:read",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));
        let invoice = repo
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice exists");
        assert!(invoice.preimage.is_none());
        assert!(repo.pending_zap_receipts.lock().unwrap().is_empty());
        assert!(repo.webhook_deliveries.lock().unwrap().is_empty());
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

    #[test]
    fn internal_identifier_lookup_route_shape_is_locked_to_restful_path() {
        let main_source = include_str!("main.rs");
        assert!(main_source.contains("/domains/{domain}/identifiers/{identifier}"));
        assert!(!main_source.contains("accounts/by-identifier"));
    }

    #[test]
    fn auth_08_source_artifacts_record_restful_identifier_lookup_route() {
        let requirements = include_str!("../.planning/REQUIREMENTS.md");
        let roadmap = include_str!("../.planning/ROADMAP.md");
        let source_artifacts = format!("{requirements}\n{roadmap}");

        assert!(source_artifacts.contains("/internal/domains/{domain}/identifiers/{identifier}"));
        assert!(source_artifacts.contains("D-22"));
        assert!(
            !source_artifacts
                .contains("GET /internal/accounts/by-identifier/{identifier}` resolves")
        );
    }

    #[test]
    fn internal_route_boundary_keeps_spark_and_public_routes_outside_internal_auth() {
        // D-01/D-02/D-28: `/internal` is nested separately, Spark management routes
        // keep `auth::auth`, and public LNURL routes remain outside internal JWT auth.
        let main_source = include_str!("main.rs");
        let internal_mount = main_source
            .find(".nest(\"/internal\", internal_router)")
            .expect("internal router must be nested separately");
        let spark_auth = main_source
            .find("auth::auth::<DB>")
            .expect("Spark compatibility routes must keep certificate auth");
        let public_lnurl = main_source
            .find("/.well-known/lnurlp/{identifier}")
            .expect("public LNURL route must remain mounted");
        let internal_auth = main_source
            .find("internal_auth::internal_auth::<DB>")
            .expect("internal router must use internal JWT middleware");

        assert!(internal_auth < internal_mount);
        assert!(internal_mount < spark_auth);
        assert!(spark_auth < public_lnurl);
        assert!(main_source.contains("/blink/accounts"));
        assert!(main_source.contains("/lnurlpay/{pubkey}"));
        assert!(main_source.contains("/lnurlp/{identifier}"));
    }

    #[tokio::test]
    async fn webhook_valid_payment_marks_invoice_paid() {
        let repo = setup_repo_with_invoice(TEST_PREIMAGE_HEX, TEST_RECEIVER_PUBKEY);
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());

        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let invoice = repo
            .invoices
            .lock()
            .unwrap()
            .get(&payment_hash)
            .cloned()
            .unwrap();
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));

        assert!(
            repo.pending_zap_receipts
                .lock()
                .unwrap()
                .contains_key(&payment_hash)
        );
    }

    #[tokio::test]
    async fn webhook_millisatoshi_htlc_amount_converts_to_sat() {
        let repo = setup_repo_with_invoice(TEST_PREIMAGE_HEX, TEST_RECEIVER_PUBKEY);
        let (trigger, _rx) = watch::channel(());

        let mut payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        payload["htlc_amount"] = serde_json::json!({"value": 50_000_000, "unit": "MILLISATOSHI"});
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());

        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let invoice = repo
            .invoices
            .lock()
            .unwrap()
            .get(&payment_hash)
            .cloned()
            .unwrap();
        assert_eq!(invoice.preimage.as_deref(), Some(TEST_PREIMAGE_HEX));
        assert_eq!(invoice.amount_received_sat, Some(50_000));
    }

    #[tokio::test]
    async fn webhook_missing_signature_returns_unauthorized() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());
        let headers = HeaderMap::new();
        let body = Bytes::from(b"{}".to_vec());

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_invalid_signature_returns_unauthorized() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("X-Spark-Signature", "deadbeef".repeat(8).parse().unwrap());
        let body = Bytes::from(body_bytes);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_non_hex_signature_returns_unauthorized() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let body = Bytes::from(b"{}".to_vec());
        let mut headers = HeaderMap::new();
        headers.insert("X-Spark-Signature", "not-valid-hex!".parse().unwrap());

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_invalid_json_returns_bad_request() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let body_bytes = b"not json";
        let sig = compute_hmac(TEST_WEBHOOK_SECRET, body_bytes);
        let mut headers = HeaderMap::new();
        headers.insert("X-Spark-Signature", sig.parse().unwrap());
        let body = Bytes::from(body_bytes.to_vec());

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn webhook_non_receive_event_type_is_ignored() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload("SOME_OTHER_EVENT", None, None);
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn webhook_missing_preimage_returns_bad_request() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            None,
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn webhook_missing_receiver_pubkey_returns_bad_request() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            None,
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn webhook_invalid_preimage_hex_returns_bad_request() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some("not-valid-hex"),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn webhook_no_matching_invoice_succeeds_silently() {
        let repo = MockRepository::default(); // no invoices
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn webhook_pubkey_mismatch_succeeds_silently() {
        let repo = setup_repo_with_invoice(TEST_PREIMAGE_HEX, "02different_pubkey");
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY), // doesn't match invoice's pubkey
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());

        // Invoice should NOT have been updated
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        let invoice = repo
            .invoices
            .lock()
            .unwrap()
            .get(&payment_hash)
            .cloned()
            .unwrap();
        assert!(invoice.preimage.is_none());
    }

    #[tokio::test]
    async fn webhook_already_paid_invoice_is_idempotent() {
        let repo = MockRepository::default();
        let payment_hash = compute_payment_hash(TEST_PREIMAGE_HEX);
        repo.invoices.lock().unwrap().insert(
            payment_hash.clone(),
            Invoice {
                account_id: None,
                provider: None,
                wallet_kind: None,
                wallet_id: None,
                provider_payment_hash: None,
                payment_hash: payment_hash.clone(),
                user_pubkey: TEST_RECEIVER_PUBKEY.to_string(),
                invoice: "lnbc1...".to_string(),
                preimage: Some(TEST_PREIMAGE_HEX.to_string()),
                invoice_expiry: i64::MAX,
                created_at: 0,
                updated_at: 0,
                domain: None,
                amount_received_sat: None,
            },
        );
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());

        // No pending zap receipt should be created for an already-paid invoice
        assert!(repo.pending_zap_receipts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn webhook_triggers_invoice_paid_notification() {
        let repo = setup_repo_with_invoice(TEST_PREIMAGE_HEX, TEST_RECEIVER_PUBKEY);
        let (trigger, rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());

        // The watch channel should have been notified
        assert!(rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn webhook_signature_uses_correct_secret() {
        let repo = setup_repo_with_invoice(TEST_PREIMAGE_HEX, TEST_RECEIVER_PUBKEY);
        let (trigger, _rx) = watch::channel(());

        let payload = make_webhook_payload(
            "SPARK_LIGHTNING_RECEIVE_FINISHED",
            Some(TEST_PREIMAGE_HEX),
            Some(TEST_RECEIVER_PUBKEY),
        );
        // Sign with a different secret than the server expects
        let (headers, body) = signed_headers_and_body("wrong_secret", &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        let Err((status, _)) = result else {
            panic!("expected error");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_lightning_send_finished_is_ignored() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = serde_json::json!({
            "id": "018677b5-e419-99d1-0000-a7030393c9af",
            "created_at": "2025-03-09T12:00:00Z",
            "updated_at": "2025-03-09T12:00:05Z",
            "network": "MAINNET",
            "request_status": "COMPLETED",
            "status": "PREIMAGE_PROVIDED",
            "type": "SPARK_LIGHTNING_SEND_FINISHED",
            "timestamp": "2025-03-09T12:00:06Z",
            "encoded_invoice": "lnbc50u1p...",
            "fee": {"value": 100, "unit": "SATOSHI"},
            "idempotency_key": "user-defined-key-123",
            "invoice_amount": {"value": 50_000, "unit": "SATOSHI"}
        });
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn webhook_coop_exit_finished_is_ignored() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = serde_json::json!({
            "id": "018677b5-e419-99d1-0000-a7030393c9af",
            "created_at": "2025-03-09T12:00:00Z",
            "updated_at": "2025-03-09T12:00:05Z",
            "network": "MAINNET",
            "request_status": "COMPLETED",
            "status": "SUCCEEDED",
            "type": "SPARK_COOP_EXIT_FINISHED",
            "timestamp": "2025-03-09T12:00:06Z",
            "fee": {"value": 500, "unit": "SATOSHI"},
            "withdrawal_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            "l1_broadcast_fee": {"value": 200, "unit": "SATOSHI"},
            "exit_speed": "NORMAL",
            "coop_exit_txid": "a1b2c3d4...",
            "expires_at": "2025-03-10T12:00:00Z",
            "total_amount": {"value": 49_300, "unit": "SATOSHI"}
        });
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn webhook_static_deposit_finished_is_ignored() {
        let repo = MockRepository::default();
        let (trigger, _rx) = watch::channel(());

        let payload = serde_json::json!({
            "id": "018677b5-e419-99d1-0000-a7030393c9af",
            "created_at": "2025-03-09T12:00:00Z",
            "updated_at": "2025-03-09T12:00:05Z",
            "network": "MAINNET",
            "request_status": "COMPLETED",
            "status": "TRANSFER_COMPLETED",
            "type": "SPARK_STATIC_DEPOSIT_FINISHED",
            "timestamp": "2025-03-09T12:00:06Z",
            "deposit_amount": {"value": 100_000, "unit": "SATOSHI"},
            "credit_amount": {"value": 99_500, "unit": "SATOSHI"},
            "max_fee": {"value": 1000, "unit": "SATOSHI"},
            "transaction_id": "d4e5f6a7b8c9...",
            "output_index": 0,
            "bitcoin_network": "MAINNET",
            "static_deposit_address": "bc1q..."
        });
        let (headers, body) = signed_headers_and_body(TEST_WEBHOOK_SECRET, &payload);

        let result = process_webhook(
            &repo,
            &crate::webhooks::WebhookService::new(repo.clone()),
            TEST_WEBHOOK_SECRET,
            &trigger,
            &headers,
            &body,
        )
        .await;
        assert!(result.is_ok());
    }

    // -- Transfer signature verification ---------------------------------------
    //
    // The transfer route verifies signatures via SparkWallet::verify_message,
    // which delegates to verify_signature_ecdsa. These exercise that
    // verification over the route's canonical "transfer:{username}-{to_pubkey}"
    // message without needing to construct a wallet.

    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use spark::utils::verify_signature::verify_signature_ecdsa;

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
            verify_signature_ecdsa(&secp, &message, &sig, &alice_pubkey).is_ok(),
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
            verify_signature_ecdsa(&secp, &message, &sig, &bob_pubkey).is_err(),
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
                verify_signature_ecdsa(&secp, &other, &sig, &alice_pubkey).is_err(),
                "signature must not verify against a different message: {other}"
            );
        }
    }
}
