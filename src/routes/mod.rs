mod account;
mod internal;
mod lnurl_pay;
#[cfg(test)]
mod test_support;
mod webhook;
mod zap;
#[allow(unused_imports)]
pub use lnurl_pay::{LnurlPayCallbackParams, PayResponse, Tag};
use std::marker::PhantomData;
#[cfg(test)]
#[allow(unused_imports)]
use webhook::process_webhook;
#[allow(unused_imports)]
pub use webhook::{BlinkInvoiceWebhookPayload, BlinkInvoiceWebhookStatus};

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

pub struct LnurlServer<DB> {
    db: PhantomData<DB>,
}
