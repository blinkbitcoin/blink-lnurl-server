#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::anyhow;

use crate::models::ListMetadataMetadata;

use crate::user::User;
use crate::zap::Zap;

#[derive(Debug, thiserror::Error)]
pub enum LnurlRepositoryError {
    #[error("identifier conflict")]
    IdentifierConflict,
    #[error("blink account already exists")]
    BlinkAccountExists,
    #[error("account not found")]
    AccountNotFound,
    #[error("invalid ownership")]
    InvalidOwnership,
    #[error("invalid provider")]
    InvalidProvider,
    #[error("invalid identifier kind")]
    InvalidIdentifierKind,
    #[error("name taken")]
    NameTaken,
    #[error("source user does not own this username")]
    SourceNotOwner,
    #[error("database error: {0}")]
    General(anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountProvider {
    Spark,
    Blink,
}

impl AccountProvider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spark => "spark",
            Self::Blink => "blink",
        }
    }

    pub fn from_database_value(value: &str) -> Result<Self, LnurlRepositoryError> {
        match value {
            "spark" => Ok(Self::Spark),
            "blink" => Ok(Self::Blink),
            _ => Err(LnurlRepositoryError::InvalidProvider),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountIdentifierKind {
    Username,
    Phone,
}

impl AccountIdentifierKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Phone => "phone",
        }
    }

    pub fn from_database_value(value: &str) -> Result<Self, LnurlRepositoryError> {
        match value {
            "username" => Ok(Self::Username),
            "phone" => Ok(Self::Phone),
            _ => Err(LnurlRepositoryError::InvalidIdentifierKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletKind {
    Btc,
    Usd,
}

impl WalletKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Btc => "btc",
            Self::Usd => "usd",
        }
    }

    pub fn from_database_value(value: &str) -> Result<Self, LnurlRepositoryError> {
        match value {
            "btc" => Ok(Self::Btc),
            "usd" => Ok(Self::Usd),
            _ => Err(LnurlRepositoryError::InvalidOwnership),
        }
    }
}

static ACCOUNT_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn generate_account_id(provider: AccountProvider) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = ACCOUNT_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("acct_{}_{nanos:x}_{counter:x}", provider.as_str())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub account_id: String,
    pub provider: AccountProvider,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountIdentifier {
    pub account_id: String,
    pub domain: String,
    pub identifier: String,
    pub identifier_kind: AccountIdentifierKind,
    pub description: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparkAccount {
    pub account_id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlinkAccount {
    pub account_id: String,
    pub blink_account_id: String,
    pub btc_wallet_id: String,
    pub usd_wallet_id: String,
    pub default_wallet: WalletKind,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccountIdentifier {
    pub domain: String,
    pub identifier: String,
    pub identifier_kind: AccountIdentifierKind,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSparkRegistration {
    pub account_id: Option<String>,
    pub pubkey: String,
    pub identifier: NewAccountIdentifier,
}

impl NewSparkRegistration {
    pub fn validate(&self) -> Result<(), LnurlRepositoryError> {
        if self.identifier.identifier_kind == AccountIdentifierKind::Phone {
            return Err(LnurlRepositoryError::InvalidIdentifierKind);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBlinkAccount {
    pub account_id: Option<String>,
    pub blink_account_id: String,
    pub btc_wallet_id: String,
    pub usd_wallet_id: String,
    pub default_wallet: WalletKind,
    pub identifiers: Vec<NewAccountIdentifier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRecipient {
    pub account_id: String,
    pub provider: AccountProvider,
    pub domain: String,
    pub identifier: String,
    pub identifier_kind: AccountIdentifierKind,
    pub description: String,
    pub spark_pubkey: Option<String>,
    pub blink_account_id: Option<String>,
    pub btc_wallet_id: Option<String>,
    pub usd_wallet_id: Option<String>,
    pub default_wallet: Option<WalletKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifierTransfer {
    pub domain: String,
    pub identifier: String,
    pub source_account_id: String,
    pub destination_account_id: String,
    pub description: String,
}

fn provider_neutral_not_implemented() -> LnurlRepositoryError {
    LnurlRepositoryError::General(anyhow!(
        "provider-neutral repository method not implemented"
    ))
}

pub struct LnurlSenderComment {
    pub account_id: Option<String>,
    pub comment: String,
    pub payment_hash: String,
    pub user_pubkey: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct Invoice {
    pub account_id: Option<String>,
    pub payment_hash: String,
    pub user_pubkey: String,
    pub invoice: String,
    pub preimage: Option<String>,
    pub invoice_expiry: i64,
    pub created_at: i64,
    pub updated_at: i64,
    /// The domain this invoice was created for, if any.
    pub domain: Option<String>,
    /// Amount received in satoshis (from the HTLC). NULL when unknown.
    pub amount_received_sat: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct PendingZapReceipt {
    pub payment_hash: String,
    pub created_at: i64,
    pub retry_count: i32,
    pub next_retry_at: i64,
}

#[async_trait::async_trait]
pub trait LnurlRepository {
    async fn delete_user(&self, domain: &str, pubkey: &str) -> Result<(), LnurlRepositoryError>;
    async fn get_user_by_name(
        &self,
        domain: &str,
        name: &str,
    ) -> Result<Option<User>, LnurlRepositoryError>;
    async fn get_user_by_pubkey(
        &self,
        domain: &str,
        pubkey: &str,
    ) -> Result<Option<User>, LnurlRepositoryError>;
    async fn upsert_user(&self, user: &User) -> Result<(), LnurlRepositoryError>;

    async fn resolve_recipient_by_identifier(
        &self,
        _domain: &str,
        _identifier: &str,
    ) -> Result<Option<ResolvedRecipient>, LnurlRepositoryError> {
        Err(provider_neutral_not_implemented())
    }

    async fn get_account_by_id(
        &self,
        _account_id: &str,
    ) -> Result<Option<Account>, LnurlRepositoryError> {
        Err(provider_neutral_not_implemented())
    }

    async fn get_account_by_spark_pubkey(
        &self,
        _pubkey: &str,
    ) -> Result<Option<Account>, LnurlRepositoryError> {
        Err(provider_neutral_not_implemented())
    }

    async fn upsert_spark_registration(
        &self,
        registration: &NewSparkRegistration,
    ) -> Result<(), LnurlRepositoryError> {
        registration.validate()?;
        Err(provider_neutral_not_implemented())
    }

    async fn create_blink_account(
        &self,
        _account: &NewBlinkAccount,
    ) -> Result<(), LnurlRepositoryError> {
        Err(provider_neutral_not_implemented())
    }

    async fn delete_spark_registration(
        &self,
        _domain: &str,
        _pubkey: &str,
    ) -> Result<(), LnurlRepositoryError> {
        Err(provider_neutral_not_implemented())
    }

    async fn transfer_identifier(
        &self,
        _transfer: &IdentifierTransfer,
    ) -> Result<(), LnurlRepositoryError> {
        Err(provider_neutral_not_implemented())
    }

    /// Atomically transfer ownership of `username` in `domain` from `from_pubkey`
    /// to `to_pubkey`, replacing any existing row for `to_pubkey`.
    /// Returns [`LnurlRepositoryError::SourceNotOwner`] if `from_pubkey` does not
    /// currently own `username` in `domain`.
    async fn transfer_username(
        &self,
        domain: &str,
        from_pubkey: &str,
        to_pubkey: &str,
        username: &str,
        description: &str,
    ) -> Result<(), LnurlRepositoryError>;

    async fn upsert_zap(&self, zap: &Zap) -> Result<(), LnurlRepositoryError>;
    async fn get_zap_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<Option<Zap>, LnurlRepositoryError>;
    async fn insert_lnurl_sender_comment(
        &self,
        comment: &LnurlSenderComment,
    ) -> Result<(), LnurlRepositoryError>;
    async fn get_metadata_by_pubkey(
        &self,
        pubkey: &str,
        offset: u32,
        limit: u32,
        updated_after: Option<i64>,
    ) -> Result<Vec<ListMetadataMetadata>, LnurlRepositoryError>;

    /// Get all allowed domains from the database
    async fn list_domains(&self) -> Result<Vec<String>, LnurlRepositoryError>;

    /// Insert a domain if it doesn't already exist
    async fn add_domain(&self, domain: &str) -> Result<(), LnurlRepositoryError>;

    /// Filter a list of payment hashes to only those the server already knows about
    /// (i.e. have an existing invoice, zap, or sender comment record).
    async fn filter_known_payment_hashes(
        &self,
        payment_hashes: &[String],
    ) -> Result<Vec<String>, LnurlRepositoryError>;

    /// Insert or update an invoice
    async fn upsert_invoice(&self, invoice: &Invoice) -> Result<(), LnurlRepositoryError>;

    /// Batch upsert invoices with preimages. Inserts new records, or updates existing
    /// ones only if they belong to the same user and don't already have a preimage.
    /// Returns payment hashes that were actually inserted or updated.
    async fn upsert_invoices_paid(
        &self,
        invoices: &[Invoice],
    ) -> Result<Vec<String>, LnurlRepositoryError>;

    /// Get an invoice by payment hash
    async fn get_invoice_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<Option<Invoice>, LnurlRepositoryError>;

    /// Get both the zap and invoice for a payment hash in a single query
    async fn get_zap_and_invoice_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<(Option<Zap>, Option<Invoice>), LnurlRepositoryError>;
    /// Insert a pending zap receipt into the queue
    async fn insert_pending_zap_receipt(
        &self,
        pending: &PendingZapReceipt,
    ) -> Result<(), LnurlRepositoryError>;

    /// Batch insert pending zap receipts into the queue
    async fn insert_pending_zap_receipt_batch(
        &self,
        pending: &[PendingZapReceipt],
    ) -> Result<(), LnurlRepositoryError>;

    /// Get pending zap receipts ready for processing (`next_retry_at` <= now),
    /// atomically claiming them. Items already claimed by another instance
    /// within the last 5 minutes are skipped.
    async fn take_pending_zap_receipts(
        &self,
        limit: u32,
    ) -> Result<Vec<PendingZapReceipt>, LnurlRepositoryError>;

    /// Update retry count and next retry time for a pending zap receipt
    async fn update_pending_zap_receipt_retry(
        &self,
        payment_hash: &str,
        retry_count: i32,
        next_retry_at: i64,
    ) -> Result<(), LnurlRepositoryError>;

    /// Delete a pending zap receipt from the queue
    async fn delete_pending_zap_receipt(
        &self,
        payment_hash: &str,
    ) -> Result<(), LnurlRepositoryError>;

    /// Get or create a setting. If the key doesn't exist, insert the default value.
    /// Returns the current value (either existing or newly inserted).
    async fn get_or_create_setting(
        &self,
        key: &str,
        default_value: &str,
    ) -> Result<String, LnurlRepositoryError>;

    /// Get data needed to build webhook payloads for the given payment hashes.
    /// Joins invoices, users, `sender_comments`, and `domain_webhooks`.
    /// Returns rows for invoices that have a domain and a preimage.
    async fn get_webhook_payloads(
        &self,
        payment_hashes: &[String],
    ) -> Result<Vec<WebhookPayloadData>, LnurlRepositoryError>;
}

/// Data returned by the webhook enqueue query.
pub struct WebhookPayloadData {
    pub account_id: Option<String>,
    pub payment_hash: String,
    pub user_pubkey: String,
    pub invoice: String,
    pub preimage: String,
    pub amount_received_sat: Option<i64>,
    pub lightning_address: Option<String>,
    pub sender_comment: Option<String>,
    pub domain: String,
}

#[cfg(test)]
pub mod shared_tests {
    use super::{
        AccountIdentifierKind, AccountProvider, IdentifierTransfer, Invoice, LnurlRepository,
        LnurlRepositoryError, LnurlSenderComment, NewAccountIdentifier, NewBlinkAccount,
        NewSparkRegistration, WalletKind, generate_account_id,
    };
    use crate::zap::Zap;

    pub async fn identifier_conflict_is_global<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // D-10/D-18/D-19: identical (domain, identifier) ownership across
        // providers must surface as an exact IdentifierConflict domain error.
        let identifier = NewAccountIdentifier {
            domain: "conflict.example.com".to_string(),
            identifier: "alice".to_string(),
            identifier_kind: AccountIdentifierKind::Username,
            description: "spark alice".to_string(),
        };
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(generate_account_id(AccountProvider::Spark)),
            pubkey: "spark_conflict_pubkey".to_string(),
            identifier: identifier.clone(),
        })
        .await
        .unwrap();

        let result = db
            .create_blink_account(&NewBlinkAccount {
                account_id: Some(generate_account_id(AccountProvider::Blink)),
                blink_account_id: "blink_conflict_account".to_string(),
                btc_wallet_id: "blink_conflict_btc".to_string(),
                usd_wallet_id: "blink_conflict_usd".to_string(),
                default_wallet: WalletKind::Btc,
                identifiers: vec![identifier],
            })
            .await;
        assert!(matches!(
            result,
            Err(LnurlRepositoryError::IdentifierConflict)
        ));
    }

    pub async fn spark_registration_dual_writes_provider_neutral_rows<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // D-15/D-17/D-19: Spark compatibility registration must create the
        // provider-neutral account, Spark child row, and identifier row atomically.
        let account_id = generate_account_id(AccountProvider::Spark);
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(account_id.clone()),
            pubkey: "spark_dual_write_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "dual.example.com".to_string(),
                identifier: "alice".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "dual write".to_string(),
            },
        })
        .await
        .unwrap();

        let recipient = db
            .resolve_recipient_by_identifier("dual.example.com", "alice")
            .await
            .unwrap()
            .expect("recipient must resolve by claimed identifier");
        assert_eq!(recipient.account_id, account_id);
        assert_eq!(recipient.provider, AccountProvider::Spark);
        assert_eq!(recipient.description, "dual write");
        assert_eq!(
            recipient.spark_pubkey.as_deref(),
            Some("spark_dual_write_pubkey")
        );
        assert!(recipient.blink_account_id.is_none());
    }

    pub async fn spark_phone_identifier_is_rejected<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // D-06/D-07/D-18: phone is an explicit kind, but Spark ownership of
        // phone identifiers must be rejected at the repository boundary.
        let result = db
            .upsert_spark_registration(&NewSparkRegistration {
                account_id: Some(generate_account_id(AccountProvider::Spark)),
                pubkey: "spark_phone_pubkey".to_string(),
                identifier: NewAccountIdentifier {
                    domain: "phone.example.com".to_string(),
                    identifier: "+573005871212".to_string(),
                    identifier_kind: AccountIdentifierKind::Phone,
                    description: "phone should fail".to_string(),
                },
            })
            .await;
        assert!(matches!(
            result,
            Err(LnurlRepositoryError::InvalidIdentifierKind)
        ));
    }

    pub async fn blink_account_creation_is_atomic<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // D-03/D-17/D-19: Blink account creation persists Blink natural keys,
        // wallet ids, default wallet, and all identifiers in one transaction.
        let account_id = generate_account_id(AccountProvider::Blink);
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some(account_id.clone()),
            blink_account_id: "blink_atomic_account".to_string(),
            btc_wallet_id: "blink_atomic_btc".to_string(),
            usd_wallet_id: "blink_atomic_usd".to_string(),
            default_wallet: WalletKind::Usd,
            identifiers: vec![NewAccountIdentifier {
                domain: "atomic.example.com".to_string(),
                identifier: "bob".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "blink bob".to_string(),
            }],
        })
        .await
        .unwrap();

        let recipient = db
            .resolve_recipient_by_identifier("atomic.example.com", "bob")
            .await
            .unwrap()
            .expect("blink recipient must resolve by identifier");
        assert_eq!(recipient.account_id, account_id);
        assert_eq!(recipient.provider, AccountProvider::Blink);
        assert_eq!(
            recipient.blink_account_id.as_deref(),
            Some("blink_atomic_account")
        );
        assert_eq!(recipient.btc_wallet_id.as_deref(), Some("blink_atomic_btc"));
        assert_eq!(recipient.usd_wallet_id.as_deref(), Some("blink_atomic_usd"));
        assert_eq!(recipient.default_wallet, Some(WalletKind::Usd));
        assert!(recipient.spark_pubkey.is_none());
    }

    pub async fn blink_duplicate_account_returns_blink_account_exists<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // D-18/D-19: duplicate Blink natural keys are distinct from global
        // identifier conflicts and must return BlinkAccountExists.
        let account = NewBlinkAccount {
            account_id: Some(generate_account_id(AccountProvider::Blink)),
            blink_account_id: "blink_duplicate_account".to_string(),
            btc_wallet_id: "blink_duplicate_btc".to_string(),
            usd_wallet_id: "blink_duplicate_usd".to_string(),
            default_wallet: WalletKind::Btc,
            identifiers: vec![NewAccountIdentifier {
                domain: "duplicate.example.com".to_string(),
                identifier: "carol".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "first".to_string(),
            }],
        };
        db.create_blink_account(&account).await.unwrap();

        let result = db
            .create_blink_account(&NewBlinkAccount {
                account_id: Some(generate_account_id(AccountProvider::Blink)),
                identifiers: vec![NewAccountIdentifier {
                    domain: "duplicate.example.com".to_string(),
                    identifier: "dave".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "second".to_string(),
                }],
                ..account
            })
            .await;
        assert!(matches!(
            result,
            Err(LnurlRepositoryError::BlinkAccountExists)
        ));
    }

    pub async fn lookup_by_identifier_account_id_and_spark_pubkey_round_trips<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // D-15/D-19: callers can resolve the same Spark account by identifier,
        // provider-neutral account id, and provider-specific Spark pubkey.
        let account_id = generate_account_id(AccountProvider::Spark);
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(account_id.clone()),
            pubkey: "spark_lookup_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "lookup.example.com".to_string(),
                identifier: "erin".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "lookup".to_string(),
            },
        })
        .await
        .unwrap();

        let recipient = db
            .resolve_recipient_by_identifier("lookup.example.com", "erin")
            .await
            .unwrap()
            .expect("identifier lookup should find account");
        let by_id = db
            .get_account_by_id(&account_id)
            .await
            .unwrap()
            .expect("account id lookup should find account");
        let by_pubkey = db
            .get_account_by_spark_pubkey("spark_lookup_pubkey")
            .await
            .unwrap()
            .expect("Spark pubkey lookup should find account");
        assert_eq!(recipient.account_id, account_id);
        assert_eq!(by_id.account_id, account_id);
        assert_eq!(by_pubkey.account_id, account_id);
    }

    pub async fn transfer_identifier_requires_source_owner<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // D-17/D-18/D-19: transfer is explicit and must prove the source owner
        // before moving an identifier to a destination account.
        let result = db
            .transfer_identifier(&IdentifierTransfer {
                domain: "transfer.example.com".to_string(),
                identifier: "frank".to_string(),
                source_account_id: "not_the_owner".to_string(),
                destination_account_id: "destination".to_string(),
                description: "transfer".to_string(),
            })
            .await;
        assert!(matches!(result, Err(LnurlRepositoryError::SourceNotOwner)));
    }

    #[allow(clippy::too_many_lines)]
    pub async fn side_effect_records_round_trip_account_id<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // D-17/D-19: later backend implementations must preserve nullable
        // provider-neutral ownership on side-effect records while legacy
        // user_pubkey fields remain available during migration.
        let account_id = generate_account_id(AccountProvider::Spark);
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(account_id.clone()),
            pubkey: "spark_side_effect_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "effects.example.com".to_string(),
                identifier: "grace".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "side effects".to_string(),
            },
        })
        .await
        .unwrap();

        let account = db
            .get_account_by_id(&account_id)
            .await
            .unwrap()
            .expect("account should remain addressable after side-effect writes");
        assert_eq!(account.account_id, account_id);

        let now = crate::time::now_millis();
        let payment_hash = "side_effect_account_hash".to_string();

        db.upsert_invoice(&Invoice {
            account_id: Some(account_id.clone()),
            payment_hash: payment_hash.clone(),
            user_pubkey: "spark_side_effect_pubkey".to_string(),
            invoice: "lnbc1sideeffect".to_string(),
            preimage: Some("side_effect_preimage".to_string()),
            invoice_expiry: i64::MAX,
            created_at: now,
            updated_at: now,
            domain: Some("effects.example.com".to_string()),
            amount_received_sat: None,
        })
        .await
        .unwrap();
        db.upsert_zap(&Zap {
            account_id: Some(account_id.clone()),
            payment_hash: payment_hash.clone(),
            zap_request: r#"{"kind":9734}"#.to_string(),
            zap_event: None,
            user_pubkey: "spark_side_effect_pubkey".to_string(),
            invoice_expiry: i64::MAX,
            updated_at: now,
            is_user_nostr_key: false,
        })
        .await
        .unwrap();
        db.insert_lnurl_sender_comment(&LnurlSenderComment {
            account_id: Some(account_id.clone()),
            comment: "provider-neutral comment".to_string(),
            payment_hash: payment_hash.clone(),
            user_pubkey: "spark_side_effect_pubkey".to_string(),
            updated_at: now,
        })
        .await
        .unwrap();

        let invoice = db
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should round-trip");
        assert_eq!(invoice.account_id.as_deref(), Some(account_id.as_str()));
        assert_eq!(invoice.user_pubkey, "spark_side_effect_pubkey");

        let zap = db
            .get_zap_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("zap should round-trip");
        assert_eq!(zap.account_id.as_deref(), Some(account_id.as_str()));
        assert_eq!(zap.user_pubkey, "spark_side_effect_pubkey");

        let webhook_payloads = db
            .get_webhook_payloads(std::slice::from_ref(&payment_hash))
            .await
            .unwrap();
        let webhook_payload = webhook_payloads
            .first()
            .expect("paid invoice should be eligible for webhook payloads");
        assert_eq!(
            webhook_payload.account_id.as_deref(),
            Some(account_id.as_str())
        );
        assert_eq!(
            webhook_payload.sender_comment.as_deref(),
            Some("provider-neutral comment")
        );

        db.upsert_invoice(&Invoice {
            account_id: None,
            payment_hash: payment_hash.clone(),
            user_pubkey: "spark_side_effect_pubkey".to_string(),
            invoice: "lnbc1sideeffect-updated".to_string(),
            preimage: Some("side_effect_preimage".to_string()),
            invoice_expiry: i64::MAX,
            created_at: now,
            updated_at: now.saturating_add(1),
            domain: Some("effects.example.com".to_string()),
            amount_received_sat: Some(21),
        })
        .await
        .unwrap();
        db.upsert_zap(&Zap {
            account_id: None,
            payment_hash: payment_hash.clone(),
            zap_request: r#"{"kind":9734}"#.to_string(),
            zap_event: Some(r#"{"kind":9735}"#.to_string()),
            user_pubkey: "spark_side_effect_pubkey".to_string(),
            invoice_expiry: i64::MAX,
            updated_at: now.saturating_add(1),
            is_user_nostr_key: false,
        })
        .await
        .unwrap();
        db.insert_lnurl_sender_comment(&LnurlSenderComment {
            account_id: None,
            comment: "legacy comment update".to_string(),
            payment_hash: payment_hash.clone(),
            user_pubkey: "spark_side_effect_pubkey".to_string(),
            updated_at: now.saturating_add(1),
        })
        .await
        .unwrap();

        let updated_invoice = db
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("updated invoice should round-trip");
        assert_eq!(
            updated_invoice.account_id.as_deref(),
            Some(account_id.as_str()),
            "legacy invoice updates must not clear existing provider-neutral ownership"
        );
        let updated_zap = db
            .get_zap_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("updated zap should round-trip");
        assert_eq!(
            updated_zap.account_id.as_deref(),
            Some(account_id.as_str()),
            "legacy zap updates must not clear existing provider-neutral ownership"
        );
        let updated_webhook_payloads = db.get_webhook_payloads(&[payment_hash]).await.unwrap();
        let updated_webhook_payload = updated_webhook_payloads
            .first()
            .expect("updated paid invoice should remain eligible for webhook payloads");
        assert_eq!(
            updated_webhook_payload.account_id.as_deref(),
            Some(account_id.as_str()),
            "legacy comment updates must not clear webhook ownership context"
        );
    }
}

#[cfg(test)]
pub mod provider_neutral_schema_tests {
    use sqlx::{Row, SqlitePool};

    const ACCOUNT_TABLES: &[&str] = &[
        "accounts",
        "account_identifiers",
        "spark_accounts",
        "blink_accounts",
    ];

    const SIDE_EFFECT_TABLES: &[&str] = &["invoices", "zaps", "sender_comments"];

    struct TableExpectation<'a> {
        name: &'a str,
        required_columns: &'a [&'a str],
        forbidden_columns: &'a [&'a str],
    }

    const ACCOUNT_EXPECTATIONS: &[TableExpectation<'_>] = &[
        TableExpectation {
            name: "accounts",
            required_columns: &["account_id", "provider", "created_at", "updated_at"],
            forbidden_columns: &["description", "deleted_at"],
        },
        TableExpectation {
            name: "account_identifiers",
            required_columns: &[
                "account_id",
                "domain",
                "identifier",
                "identifier_kind",
                "description",
                "created_at",
                "updated_at",
            ],
            forbidden_columns: &["deleted_at"],
        },
        TableExpectation {
            name: "spark_accounts",
            required_columns: &["account_id", "pubkey", "created_at", "updated_at"],
            forbidden_columns: &["deleted_at"],
        },
        TableExpectation {
            name: "blink_accounts",
            required_columns: &[
                "account_id",
                "blink_account_id",
                "btc_wallet_id",
                "usd_wallet_id",
                "default_wallet",
                "created_at",
                "updated_at",
            ],
            forbidden_columns: &["deleted_at"],
        },
    ];

    #[tokio::test]
    async fn sqlite_provider_neutral_schema_migrates() {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        crate::sqlite::run_migrations(&pool).await.unwrap();

        provider_neutral_schema_migrates(SqlSchema::Sqlite(&pool)).await;
    }

    #[tokio::test]
    async fn postgres_provider_neutral_schema_migrates() {
        let Some(url) = std::env::var("LNURL_TEST_POSTGRES_URL").ok() else {
            return;
        };
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        crate::postgresql::run_migrations(&pool).await.unwrap();

        provider_neutral_schema_migrates(SqlSchema::Postgres(&pool)).await;
    }

    enum SqlSchema<'a> {
        Sqlite(&'a SqlitePool),
        Postgres(&'a sqlx::PgPool),
    }

    async fn provider_neutral_schema_migrates(schema: SqlSchema<'_>) {
        match schema {
            SqlSchema::Sqlite(pool) => assert_sqlite_schema(pool).await,
            SqlSchema::Postgres(pool) => assert_postgres_schema(pool).await,
        }
    }

    async fn assert_sqlite_schema(pool: &SqlitePool) {
        for table in ACCOUNT_TABLES {
            assert!(
                sqlite_table_exists(pool, table).await,
                "missing table {table}"
            );
        }

        for expectation in ACCOUNT_EXPECTATIONS {
            let columns = sqlite_columns(pool, expectation.name).await;
            assert_columns(expectation.name, &columns, expectation.required_columns);
            assert_no_columns(expectation.name, &columns, expectation.forbidden_columns);
        }

        for table in SIDE_EFFECT_TABLES {
            let columns = sqlite_columns(pool, table).await;
            assert_columns(table, &columns, &["account_id", "user_pubkey"]);
            let account_id = sqlite_column(pool, table, "account_id").await;
            assert_eq!(account_id.notnull, 0, "{table}.account_id must be nullable");
        }

        assert_sqlite_check_contains(pool, "accounts", "'spark'").await;
        assert_sqlite_check_contains(pool, "accounts", "'blink'").await;
        assert_sqlite_check_contains(pool, "account_identifiers", "'username'").await;
        assert_sqlite_check_contains(pool, "account_identifiers", "'phone'").await;
        assert_sqlite_check_contains(pool, "blink_accounts", "'btc'").await;
        assert_sqlite_check_contains(pool, "blink_accounts", "'usd'").await;
        assert_sqlite_index_exists(pool, "account_identifiers_domain_identifier_key").await;
        assert_sqlite_index_exists(pool, "spark_accounts_pubkey_key").await;
        assert_sqlite_index_exists(pool, "blink_accounts_blink_account_id_key").await;
        assert_sqlite_index_exists(pool, "idx_invoices_account_id").await;
        assert_sqlite_index_exists(pool, "idx_zaps_account_id").await;
        assert_sqlite_index_exists(pool, "idx_sender_comments_account_id").await;
    }

    async fn assert_postgres_schema(pool: &sqlx::PgPool) {
        for table in ACCOUNT_TABLES {
            assert!(
                postgres_table_exists(pool, table).await,
                "missing table {table}"
            );
        }

        for expectation in ACCOUNT_EXPECTATIONS {
            let columns = postgres_columns(pool, expectation.name).await;
            assert_columns(expectation.name, &columns, expectation.required_columns);
            assert_no_columns(expectation.name, &columns, expectation.forbidden_columns);
        }

        for table in SIDE_EFFECT_TABLES {
            let columns = postgres_columns(pool, table).await;
            assert_columns(table, &columns, &["account_id", "user_pubkey"]);
            assert!(
                postgres_column_is_nullable(pool, table, "account_id").await,
                "{table}.account_id must be nullable"
            );
        }

        assert_postgres_check_contains(pool, "accounts", "'spark'").await;
        assert_postgres_check_contains(pool, "accounts", "'blink'").await;
        assert_postgres_check_contains(pool, "account_identifiers", "'username'").await;
        assert_postgres_check_contains(pool, "account_identifiers", "'phone'").await;
        assert_postgres_check_contains(pool, "blink_accounts", "'btc'").await;
        assert_postgres_check_contains(pool, "blink_accounts", "'usd'").await;
        assert_postgres_index_exists(pool, "account_identifiers_domain_identifier_key").await;
        assert_postgres_index_exists(pool, "spark_accounts_pubkey_key").await;
        assert_postgres_index_exists(pool, "blink_accounts_blink_account_id_key").await;
        assert_postgres_index_exists(pool, "idx_invoices_account_id").await;
        assert_postgres_index_exists(pool, "idx_zaps_account_id").await;
        assert_postgres_index_exists(pool, "idx_sender_comments_account_id").await;
    }

    fn assert_columns(table: &str, columns: &[String], expected: &[&str]) {
        for column in expected {
            assert!(
                columns.iter().any(|actual| actual == column),
                "{table} missing column {column}; columns: {columns:?}"
            );
        }
    }

    fn assert_no_columns(table: &str, columns: &[String], forbidden: &[&str]) {
        for column in forbidden {
            assert!(
                !columns.iter().any(|actual| actual == column),
                "{table} must not expose column {column}"
            );
        }
    }

    struct SqliteColumn {
        notnull: i64,
    }

    async fn sqlite_table_exists(pool: &SqlitePool, table: &str) -> bool {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap()
            == 1
    }

    async fn sqlite_columns(pool: &SqlitePool, table: &str) -> Vec<String> {
        let query = format!("PRAGMA table_info({table})");
        sqlx::query(sqlx::AssertSqlSafe(query))
            .fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String, _>("name").unwrap())
            .collect()
    }

    async fn sqlite_column(pool: &SqlitePool, table: &str, column: &str) -> SqliteColumn {
        let query = format!("PRAGMA table_info({table})");
        let row = sqlx::query(sqlx::AssertSqlSafe(query))
            .fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.try_get::<String, _>("name").unwrap() == column)
            .unwrap_or_else(|| panic!("{table} missing column {column}"));
        SqliteColumn {
            notnull: row.try_get("notnull").unwrap(),
        }
    }

    async fn assert_sqlite_check_contains(pool: &SqlitePool, table: &str, expected: &str) {
        let sql = sqlx::query_scalar::<_, String>(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(
            sql.contains(expected),
            "{table} DDL missing {expected}: {sql}"
        );
    }

    async fn assert_sqlite_index_exists(pool: &SqlitePool, index: &str) {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?",
        )
        .bind(index)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "missing SQLite index/constraint {index}");
    }

    async fn postgres_table_exists(pool: &sqlx::PgPool, table: &str) -> bool {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap()
            == 1
    }

    async fn postgres_columns(pool: &sqlx::PgPool, table: &str) -> Vec<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1",
        )
        .bind(table)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn postgres_column_is_nullable(pool: &sqlx::PgPool, table: &str, column: &str) -> bool {
        let nullable = sqlx::query_scalar::<_, String>(
            "SELECT is_nullable FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
        )
        .bind(table)
        .bind(column)
        .fetch_one(pool)
        .await
        .unwrap();
        nullable == "YES"
    }

    async fn assert_postgres_check_contains(pool: &sqlx::PgPool, table: &str, expected: &str) {
        let definitions = sqlx::query_scalar::<_, String>(
            "SELECT pg_get_constraintdef(c.oid)
             FROM pg_constraint c
             JOIN pg_class t ON t.oid = c.conrelid
             JOIN pg_namespace n ON n.oid = t.relnamespace
             WHERE n.nspname = 'public' AND t.relname = $1 AND c.contype = 'c'",
        )
        .bind(table)
        .fetch_all(pool)
        .await
        .unwrap();
        assert!(
            definitions
                .iter()
                .any(|definition| definition.contains(expected)),
            "{table} checks missing {expected}: {definitions:?}"
        );
    }

    async fn assert_postgres_index_exists(pool: &sqlx::PgPool, index: &str) {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = $1",
        )
        .bind(index)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "missing Postgres index/constraint {index}");
    }
}
