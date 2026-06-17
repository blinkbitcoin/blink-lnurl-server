use axum::{Extension, Json, extract::Path, http::StatusCode};
use nostr::{Alphabet, Event, EventBuilder, JsonUtil, Kind, TagStandard, key::Keys};
use serde_json::{Value, json};
use tracing::{debug, error, trace, warn};

use crate::{
    invoice_paid::{HandleInvoicePaidError, handle_invoice_paid},
    models::{PublishZapReceiptRequest, PublishZapReceiptResponse},
    state::State,
    time::now_millis,
};

use super::{LnurlServer, account, lnurl_pay::lnurl_error};

impl<DB> LnurlServer<DB>
where
    DB: crate::repository::LnurlRepository
        + crate::webhooks::WebhookRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    #[allow(clippy::too_many_lines)]
    pub async fn publish_zap_receipt(
        Path((pubkey, payment_hash)): Path<(String, String)>,
        Extension(state): Extension<State<DB>>,
        Json(payload): Json<PublishZapReceiptRequest>,
    ) -> Result<Json<PublishZapReceiptResponse>, (StatusCode, Json<Value>)> {
        let pubkey = account::validate(
            &pubkey,
            &payload.signature,
            &payload.zap_receipt,
            payload.timestamp,
            &state,
        )
        .await?;

        if payload.zap_receipt.len() > super::MAX_NOSTR_EVENT_SIZE {
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
            .take(super::MAX_NOSTR_RELAYS)
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
}

pub(super) fn validate_nostr_zap_request(
    amount_msat: u64,
    event: &Event,
    expected_nostr_pubkey: bitcoin::secp256k1::XOnlyPublicKey,
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
