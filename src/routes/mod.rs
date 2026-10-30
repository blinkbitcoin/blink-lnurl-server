mod account;
mod internal;
mod lnurl_pay;
mod signed;
#[cfg(test)]
pub(crate) mod test_support;
mod webhook;
mod zap;
#[allow(unused_imports)]
pub use lnurl_pay::{LnurlPayCallbackParams, PayResponse, Tag};
pub use signed::{spawn_legacy_signature_reporter, spawn_signed_message_pruner};
use std::marker::PhantomData;
#[cfg(test)]
#[allow(unused_imports)]
use webhook::process_webhook;
#[allow(unused_imports)]
pub use webhook::{BlinkInvoiceWebhookPayload, BlinkInvoiceWebhookStatus};

/// Named locally for how it reads at the call sites, defined in `lnurl-models`
/// so this server and every Breez client bound a timestamp identically.
const ACCEPTABLE_TIME_DIFF_SECS: u64 = lnurl_models::signed_message::VALIDITY_SECS;
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

pub struct LnurlServer<DB> {
    db: PhantomData<DB>,
}
