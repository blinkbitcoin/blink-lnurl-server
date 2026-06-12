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
    pub destination_spark_pubkey: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlinkToSparkIdentifierTransfer {
    pub domain: String,
    pub identifier: String,
    pub source_account_id: String,
    pub destination_spark_pubkey: String,
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
    pub provider: Option<AccountProvider>,
    pub wallet_kind: Option<WalletKind>,
    pub wallet_id: Option<String>,
    pub provider_payment_hash: Option<String>,
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
        _identifier: &str,
    ) -> Result<(), LnurlRepositoryError> {
        Err(provider_neutral_not_implemented())
    }

    async fn transfer_identifier(
        &self,
        _transfer: &IdentifierTransfer,
    ) -> Result<(), LnurlRepositoryError> {
        Err(provider_neutral_not_implemented())
    }

    async fn transfer_blink_identifier_to_spark(
        &self,
        _transfer: &BlinkToSparkIdentifierTransfer,
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
        AccountIdentifierKind, AccountProvider, BlinkToSparkIdentifierTransfer, IdentifierTransfer,
        Invoice, LnurlRepository, LnurlRepositoryError, LnurlSenderComment, NewAccountIdentifier,
        NewBlinkAccount, NewSparkRegistration, WalletKind, generate_account_id,
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

    pub async fn spark_re_registration_replaces_stale_alias_identifier<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // CR-01/COMP-03: re-registering one Spark account to a new username
        // must remove the previous public provider-neutral alias.
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: None,
            pubkey: "spark_stale_alias_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "stale-alias.example.com".to_string(),
                identifier: "alice".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "old alias".to_string(),
            },
        })
        .await
        .unwrap();

        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: None,
            pubkey: "spark_stale_alias_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "stale-alias.example.com".to_string(),
                identifier: "bob".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "new alias".to_string(),
            },
        })
        .await
        .unwrap();

        assert!(
            db.resolve_recipient_by_identifier("stale-alias.example.com", "alice")
                .await
                .unwrap()
                .is_none(),
            "stale alias replacement must remove the old Spark identifier"
        );
        let bob = db
            .resolve_recipient_by_identifier("stale-alias.example.com", "bob")
            .await
            .unwrap()
            .expect("new Spark identifier should resolve after re-registration");
        assert_eq!(
            bob.spark_pubkey.as_deref(),
            Some("spark_stale_alias_pubkey")
        );
        assert_eq!(bob.description, "new alias");
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

    pub async fn spark_compatibility_registration_resolves_provider_neutral_owner<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // TEST-02/D-15: Spark compatibility registration must remain visible
        // through provider-neutral recipient lookup and legacy recover lookup.
        let account_id = generate_account_id(AccountProvider::Spark);
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(account_id.clone()),
            pubkey: "spark_compatibility_owner_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "test02-spark.example.com".to_string(),
                identifier: "sparkcompat".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "Spark compatibility owner".to_string(),
            },
        })
        .await
        .unwrap();

        let recipient = db
            .resolve_recipient_by_identifier("test02-spark.example.com", "sparkcompat")
            .await
            .unwrap()
            .expect("Spark registration should resolve provider-neutral owner");
        assert_eq!(recipient.account_id, account_id);
        assert_eq!(recipient.provider, AccountProvider::Spark);
        assert_eq!(recipient.identifier_kind, AccountIdentifierKind::Username);
        assert_eq!(recipient.description, "Spark compatibility owner");
        assert_eq!(
            recipient.spark_pubkey.as_deref(),
            Some("spark_compatibility_owner_pubkey")
        );
        assert!(recipient.blink_account_id.is_none());

        let legacy_user = db
            .get_user_by_pubkey(
                "test02-spark.example.com",
                "spark_compatibility_owner_pubkey",
            )
            .await
            .unwrap()
            .expect("Spark compatibility recover lookup should still work");
        assert_eq!(legacy_user.name, "sparkcompat");
        assert_eq!(legacy_user.description, "Spark compatibility owner");
    }

    pub async fn blink_account_creation_persists_wallet_fields<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // TEST-02/D-03: Blink account creation persists provider-neutral
        // ownership plus BTC/USD/default-wallet fields for a username alias.
        let account_id = generate_account_id(AccountProvider::Blink);
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some(account_id.clone()),
            blink_account_id: "blink_test02_wallet_account".to_string(),
            btc_wallet_id: "blink_test02_btc_wallet".to_string(),
            usd_wallet_id: "blink_test02_usd_wallet".to_string(),
            default_wallet: WalletKind::Usd,
            identifiers: vec![NewAccountIdentifier {
                domain: "test02-blink.example.com".to_string(),
                identifier: "blinkwallet".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "Blink wallet owner".to_string(),
            }],
        })
        .await
        .unwrap();

        let recipient = db
            .resolve_recipient_by_identifier("test02-blink.example.com", "blinkwallet")
            .await
            .unwrap()
            .expect("Blink username should resolve provider-neutral owner");
        assert_eq!(recipient.account_id, account_id);
        assert_eq!(recipient.provider, AccountProvider::Blink);
        assert_eq!(recipient.identifier_kind, AccountIdentifierKind::Username);
        assert_eq!(
            recipient.blink_account_id.as_deref(),
            Some("blink_test02_wallet_account")
        );
        assert_eq!(
            recipient.btc_wallet_id.as_deref(),
            Some("blink_test02_btc_wallet")
        );
        assert_eq!(
            recipient.usd_wallet_id.as_deref(),
            Some("blink_test02_usd_wallet")
        );
        assert_eq!(recipient.default_wallet, Some(WalletKind::Usd));
        assert!(recipient.spark_pubkey.is_none());
    }

    pub async fn global_identifier_conflict_rejects_cross_provider_duplicate<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // TEST-02/T-09-02-01: the global (domain, identifier) uniqueness
        // invariant rejects cross-provider duplicate ownership.
        let identifier = NewAccountIdentifier {
            domain: "test02-conflict.example.com".to_string(),
            identifier: "duplicate".to_string(),
            identifier_kind: AccountIdentifierKind::Username,
            description: "Spark first owner".to_string(),
        };
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(generate_account_id(AccountProvider::Spark)),
            pubkey: "spark_test02_conflict_pubkey".to_string(),
            identifier: identifier.clone(),
        })
        .await
        .unwrap();

        let result = db
            .create_blink_account(&NewBlinkAccount {
                account_id: Some(generate_account_id(AccountProvider::Blink)),
                blink_account_id: "blink_test02_conflict_account".to_string(),
                btc_wallet_id: "blink_test02_conflict_btc".to_string(),
                usd_wallet_id: "blink_test02_conflict_usd".to_string(),
                default_wallet: WalletKind::Btc,
                identifiers: vec![identifier],
            })
            .await;
        assert!(matches!(
            result,
            Err(LnurlRepositoryError::IdentifierConflict)
        ));
    }

    pub async fn lookup_by_username_and_normalized_phone_matches<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // TEST-02/D-03: repository lookup accepts the already-normalized E.164
        // phone identifier produced by the public/internal identifier parser and
        // returns the same Blink recipient shape as a username alias.
        let account_id = generate_account_id(AccountProvider::Blink);
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some(account_id.clone()),
            blink_account_id: "blink_test02_phone_account".to_string(),
            btc_wallet_id: "blink_test02_phone_btc".to_string(),
            usd_wallet_id: "blink_test02_phone_usd".to_string(),
            default_wallet: WalletKind::Btc,
            identifiers: vec![
                NewAccountIdentifier {
                    domain: "test02-phone.example.com".to_string(),
                    identifier: "phoneuser".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "Blink username alias".to_string(),
                },
                NewAccountIdentifier {
                    domain: "test02-phone.example.com".to_string(),
                    identifier: "+573005871212".to_string(),
                    identifier_kind: AccountIdentifierKind::Phone,
                    description: "Blink normalized phone alias".to_string(),
                },
            ],
        })
        .await
        .unwrap();

        let username = db
            .resolve_recipient_by_identifier("test02-phone.example.com", "phoneuser")
            .await
            .unwrap()
            .expect("username alias should resolve");
        let phone = db
            .resolve_recipient_by_identifier("test02-phone.example.com", "+573005871212")
            .await
            .unwrap()
            .expect("normalized phone alias should resolve");

        assert_eq!(username.account_id, account_id);
        assert_eq!(phone.account_id, username.account_id);
        assert_eq!(phone.provider, AccountProvider::Blink);
        assert_eq!(phone.identifier_kind, AccountIdentifierKind::Phone);
        assert_eq!(
            phone.blink_account_id.as_deref(),
            username.blink_account_id.as_deref()
        );
        assert_eq!(
            phone.btc_wallet_id.as_deref(),
            username.btc_wallet_id.as_deref()
        );
        assert_eq!(
            phone.usd_wallet_id.as_deref(),
            username.usd_wallet_id.as_deref()
        );
        assert_eq!(phone.default_wallet, username.default_wallet);
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
                destination_spark_pubkey: "destination_pubkey".to_string(),
                description: "transfer".to_string(),
            })
            .await;
        assert!(matches!(result, Err(LnurlRepositoryError::SourceNotOwner)));
    }

    pub async fn transfer_identifier_moves_legacy_recover_ownership<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // CR-02/COMP-01: Spark transfer must update the legacy users row so
        // recover misses for the old owner and succeeds for the new owner.
        let source_account_id = generate_account_id(AccountProvider::Spark);
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(source_account_id.clone()),
            pubkey: "spark_recover_source_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "recover-transfer.example.com".to_string(),
                identifier: "carol".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "before transfer".to_string(),
            },
        })
        .await
        .unwrap();
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(generate_account_id(AccountProvider::Spark)),
            pubkey: "spark_recover_destination_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "recover-transfer.example.com".to_string(),
                identifier: "destination".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "destination current".to_string(),
            },
        })
        .await
        .unwrap();

        db.transfer_identifier(&IdentifierTransfer {
            domain: "recover-transfer.example.com".to_string(),
            identifier: "carol".to_string(),
            source_account_id,
            destination_spark_pubkey: "spark_recover_destination_pubkey".to_string(),
            description: "after transfer".to_string(),
        })
        .await
        .unwrap();

        assert!(
            db.get_user_by_pubkey(
                "recover-transfer.example.com",
                "spark_recover_source_pubkey"
            )
            .await
            .unwrap()
            .is_none(),
            "recover after transfer must miss for the old Spark owner"
        );
        let recovered = db
            .get_user_by_pubkey(
                "recover-transfer.example.com",
                "spark_recover_destination_pubkey",
            )
            .await
            .unwrap()
            .expect("recover after transfer must return the new Spark owner");
        assert_eq!(recovered.name, "carol");
        assert_eq!(recovered.description, "after transfer");
    }

    pub async fn transfer_identifier_creates_fresh_destination_spark_account<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        let source_account_id = generate_account_id(AccountProvider::Spark);
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(source_account_id.clone()),
            pubkey: "spark_fresh_transfer_source_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "fresh-transfer.example.com".to_string(),
                identifier: "freshmove".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "before fresh transfer".to_string(),
            },
        })
        .await
        .unwrap();

        db.transfer_identifier(&IdentifierTransfer {
            domain: "fresh-transfer.example.com".to_string(),
            identifier: "freshmove".to_string(),
            source_account_id: source_account_id.clone(),
            destination_spark_pubkey: "spark_fresh_transfer_destination_pubkey".to_string(),
            description: "after fresh transfer".to_string(),
        })
        .await
        .unwrap();

        let destination_account = db
            .get_account_by_spark_pubkey("spark_fresh_transfer_destination_pubkey")
            .await
            .unwrap()
            .expect("fresh transfer should create destination Spark account");
        assert_eq!(destination_account.provider, AccountProvider::Spark);
        let moved = db
            .resolve_recipient_by_identifier("fresh-transfer.example.com", "freshmove")
            .await
            .unwrap()
            .expect("transferred identifier should resolve");
        assert_eq!(moved.account_id, destination_account.account_id);
        assert_eq!(moved.description, "after fresh transfer");
        assert_eq!(
            moved.spark_pubkey.as_deref(),
            Some("spark_fresh_transfer_destination_pubkey")
        );
        assert!(
            db.get_user_by_pubkey(
                "fresh-transfer.example.com",
                "spark_fresh_transfer_source_pubkey"
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    pub async fn transfer_identifier_replaces_destination_prior_alias<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        let source_account_id = generate_account_id(AccountProvider::Spark);
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(source_account_id.clone()),
            pubkey: "spark_replace_alias_source_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "replace-transfer.example.com".to_string(),
                identifier: "newname".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "before transfer".to_string(),
            },
        })
        .await
        .unwrap();
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: None,
            pubkey: "spark_replace_alias_destination_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "replace-transfer.example.com".to_string(),
                identifier: "oldname".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "old destination alias".to_string(),
            },
        })
        .await
        .unwrap();

        db.transfer_identifier(&IdentifierTransfer {
            domain: "replace-transfer.example.com".to_string(),
            identifier: "newname".to_string(),
            source_account_id,
            destination_spark_pubkey: "spark_replace_alias_destination_pubkey".to_string(),
            description: "replacement transfer".to_string(),
        })
        .await
        .unwrap();

        assert!(
            db.resolve_recipient_by_identifier("replace-transfer.example.com", "oldname")
                .await
                .unwrap()
                .is_none(),
            "destination's prior alias should no longer resolve after transfer"
        );
        let transferred = db
            .resolve_recipient_by_identifier("replace-transfer.example.com", "newname")
            .await
            .unwrap()
            .expect("transferred username should resolve");
        assert_eq!(
            transferred.spark_pubkey.as_deref(),
            Some("spark_replace_alias_destination_pubkey")
        );
        let recovered = db
            .get_user_by_pubkey(
                "replace-transfer.example.com",
                "spark_replace_alias_destination_pubkey",
            )
            .await
            .unwrap()
            .expect("legacy recover should point to transferred identifier");
        assert_eq!(recovered.name, "newname");
        assert_eq!(recovered.description, "replacement transfer");
    }

    pub async fn transfer_blink_identifier_to_spark_creates_fresh_destination_spark_account<DB>(
        db: &DB,
    ) where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        let source_account_id = generate_account_id(AccountProvider::Blink);
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some(source_account_id.clone()),
            blink_account_id: "blink_transfer_fresh_account".to_string(),
            btc_wallet_id: "blink_transfer_fresh_btc".to_string(),
            usd_wallet_id: "blink_transfer_fresh_usd".to_string(),
            default_wallet: WalletKind::Btc,
            identifiers: vec![NewAccountIdentifier {
                domain: "blink-fresh-transfer.example.com".to_string(),
                identifier: "freshblink".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "before blink transfer".to_string(),
            }],
        })
        .await
        .unwrap();

        db.transfer_blink_identifier_to_spark(&BlinkToSparkIdentifierTransfer {
            domain: "blink-fresh-transfer.example.com".to_string(),
            identifier: "freshblink".to_string(),
            source_account_id: source_account_id.clone(),
            destination_spark_pubkey: "spark_from_blink_fresh_destination".to_string(),
            description: "after blink transfer".to_string(),
        })
        .await
        .unwrap();

        let destination_account = db
            .get_account_by_spark_pubkey("spark_from_blink_fresh_destination")
            .await
            .unwrap()
            .expect("Blink-to-Spark transfer should create destination Spark account");
        assert_eq!(destination_account.provider, AccountProvider::Spark);

        let moved = db
            .resolve_recipient_by_identifier("blink-fresh-transfer.example.com", "freshblink")
            .await
            .unwrap()
            .expect("transferred Blink identifier should resolve");
        assert_eq!(moved.account_id, destination_account.account_id);
        assert_eq!(moved.provider, AccountProvider::Spark);
        assert_eq!(moved.description, "after blink transfer");
        assert_eq!(
            moved.spark_pubkey.as_deref(),
            Some("spark_from_blink_fresh_destination")
        );
        assert!(moved.blink_account_id.is_none());
    }

    pub async fn transfer_blink_identifier_to_spark_requires_blink_source_owner<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        let missing_result = db
            .transfer_blink_identifier_to_spark(&BlinkToSparkIdentifierTransfer {
                domain: "blink-source-required.example.com".to_string(),
                identifier: "missing".to_string(),
                source_account_id: "not_the_owner".to_string(),
                destination_spark_pubkey: "spark_from_missing_blink".to_string(),
                description: "must fail".to_string(),
            })
            .await;
        assert!(matches!(
            missing_result,
            Err(LnurlRepositoryError::SourceNotOwner)
        ));

        let spark_source_account_id = generate_account_id(AccountProvider::Spark);
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(spark_source_account_id.clone()),
            pubkey: "spark_source_for_blink_transfer".to_string(),
            identifier: NewAccountIdentifier {
                domain: "blink-source-required.example.com".to_string(),
                identifier: "sparkowned".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "spark owned".to_string(),
            },
        })
        .await
        .unwrap();

        let spark_result = db
            .transfer_blink_identifier_to_spark(&BlinkToSparkIdentifierTransfer {
                domain: "blink-source-required.example.com".to_string(),
                identifier: "sparkowned".to_string(),
                source_account_id: spark_source_account_id.clone(),
                destination_spark_pubkey: "spark_from_blink_reject_destination".to_string(),
                description: "must also fail".to_string(),
            })
            .await;
        assert!(matches!(
            spark_result,
            Err(LnurlRepositoryError::InvalidOwnership)
        ));

        let still_spark = db
            .resolve_recipient_by_identifier("blink-source-required.example.com", "sparkowned")
            .await
            .unwrap()
            .expect("rejected Spark-owned transfer must leave ownership unchanged");
        assert_eq!(still_spark.account_id, spark_source_account_id);
        assert_eq!(still_spark.provider, AccountProvider::Spark);
    }

    pub async fn transfer_blink_identifier_to_spark_moves_only_requested_identifier<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        let source_account_id = generate_account_id(AccountProvider::Blink);
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some(source_account_id.clone()),
            blink_account_id: "blink_transfer_multi_account".to_string(),
            btc_wallet_id: "blink_transfer_multi_btc".to_string(),
            usd_wallet_id: "blink_transfer_multi_usd".to_string(),
            default_wallet: WalletKind::Usd,
            identifiers: vec![
                NewAccountIdentifier {
                    domain: "blink-move-only.example.com".to_string(),
                    identifier: "moving".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "moves".to_string(),
                },
                NewAccountIdentifier {
                    domain: "blink-move-only.example.com".to_string(),
                    identifier: "stays".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "stays".to_string(),
                },
            ],
        })
        .await
        .unwrap();

        db.transfer_blink_identifier_to_spark(&BlinkToSparkIdentifierTransfer {
            domain: "blink-move-only.example.com".to_string(),
            identifier: "moving".to_string(),
            source_account_id: source_account_id.clone(),
            destination_spark_pubkey: "spark_from_blink_move_only_destination".to_string(),
            description: "moved".to_string(),
        })
        .await
        .unwrap();

        let moved = db
            .resolve_recipient_by_identifier("blink-move-only.example.com", "moving")
            .await
            .unwrap()
            .expect("requested identifier should move");
        let stayed = db
            .resolve_recipient_by_identifier("blink-move-only.example.com", "stays")
            .await
            .unwrap()
            .expect("second Blink identifier should remain");

        assert_eq!(moved.provider, AccountProvider::Spark);
        assert_eq!(
            moved.spark_pubkey.as_deref(),
            Some("spark_from_blink_move_only_destination")
        );
        assert_eq!(stayed.account_id, source_account_id);
        assert_eq!(stayed.provider, AccountProvider::Blink);
        assert_eq!(stayed.description, "stays");
    }

    pub async fn transfer_blink_identifier_to_spark_preserves_historical_blink_invoice_owner<DB>(
        db: &DB,
    ) where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        let source_account_id = generate_account_id(AccountProvider::Blink);
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some(source_account_id.clone()),
            blink_account_id: "blink_transfer_invoice_account".to_string(),
            btc_wallet_id: "blink_transfer_invoice_btc".to_string(),
            usd_wallet_id: "blink_transfer_invoice_usd".to_string(),
            default_wallet: WalletKind::Usd,
            identifiers: vec![NewAccountIdentifier {
                domain: "blink-invoice-transfer.example.com".to_string(),
                identifier: "invoiceowner".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "invoice owner".to_string(),
            }],
        })
        .await
        .unwrap();

        let now = crate::time::now_millis();
        let payment_hash = "blink_transfer_invoice_hash".to_string();
        db.upsert_invoice(&Invoice {
            account_id: Some(source_account_id.clone()),
            provider: Some(AccountProvider::Blink),
            wallet_kind: Some(WalletKind::Usd),
            wallet_id: Some("blink_transfer_invoice_usd".to_string()),
            provider_payment_hash: Some("blink_provider_payment_hash".to_string()),
            payment_hash: payment_hash.clone(),
            user_pubkey: "blink_invoice_legacy_pubkey".to_string(),
            invoice: "lnbc1blinktransferinvoice".to_string(),
            preimage: None,
            invoice_expiry: i64::MAX,
            created_at: now,
            updated_at: now,
            domain: Some("blink-invoice-transfer.example.com".to_string()),
            amount_received_sat: Some(21),
        })
        .await
        .unwrap();

        db.transfer_blink_identifier_to_spark(&BlinkToSparkIdentifierTransfer {
            domain: "blink-invoice-transfer.example.com".to_string(),
            identifier: "invoiceowner".to_string(),
            source_account_id: source_account_id.clone(),
            destination_spark_pubkey: "spark_from_blink_invoice_destination".to_string(),
            description: "invoice owner moved".to_string(),
        })
        .await
        .unwrap();

        let stored = db
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should remain persisted after transfer");
        assert_eq!(
            stored.account_id.as_deref(),
            Some(source_account_id.as_str())
        );
        assert_eq!(stored.provider, Some(AccountProvider::Blink));
        assert_eq!(stored.wallet_kind, Some(WalletKind::Usd));
        assert_eq!(
            stored.wallet_id.as_deref(),
            Some("blink_transfer_invoice_usd")
        );

        let moved = db
            .resolve_recipient_by_identifier("blink-invoice-transfer.example.com", "invoiceowner")
            .await
            .unwrap()
            .expect("current identifier ownership should move to Spark");
        assert_eq!(moved.provider, AccountProvider::Spark);
        assert_ne!(moved.account_id, source_account_id);
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
            provider: None,
            wallet_kind: None,
            wallet_id: None,
            provider_payment_hash: None,
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
            provider: None,
            wallet_kind: None,
            wallet_id: None,
            provider_payment_hash: None,
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

    #[allow(clippy::too_many_lines)]
    pub async fn invoice_provider_metadata_round_trips<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // PROV-04/LNURL-05/D-11/D-12/D-13/D-15: both Spark-shaped and
        // Blink-shaped invoice rows preserve typed provider metadata without
        // introducing a raw provider JSON payload field.
        let now = crate::time::now_millis();
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some("acct_round_trip_spark".to_string()),
            pubkey: "round_trip_spark_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "round-trip.example.com".to_string(),
                identifier: "sparkmeta".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "spark metadata".to_string(),
            },
        })
        .await
        .unwrap();
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some("acct_round_trip_blink".to_string()),
            blink_account_id: "blink_round_trip_account".to_string(),
            btc_wallet_id: "blink_btc_wallet_round_trip".to_string(),
            usd_wallet_id: "blink_usd_wallet_round_trip".to_string(),
            default_wallet: WalletKind::Usd,
            identifiers: vec![NewAccountIdentifier {
                domain: "round-trip.example.com".to_string(),
                identifier: "blinkmeta".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "blink metadata".to_string(),
            }],
        })
        .await
        .unwrap();

        let spark_invoice = Invoice {
            account_id: Some("acct_round_trip_spark".to_string()),
            provider: Some(AccountProvider::Spark),
            wallet_kind: Some(WalletKind::Btc),
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash: "round_trip_spark_hash".to_string(),
            user_pubkey: "round_trip_spark_pubkey".to_string(),
            invoice: "lnbc1roundtripspark".to_string(),
            preimage: None,
            invoice_expiry: now.saturating_add(60_000),
            created_at: now,
            updated_at: now,
            domain: Some("round-trip.example.com".to_string()),
            amount_received_sat: None,
        };
        let blink_invoice = Invoice {
            account_id: Some("acct_round_trip_blink".to_string()),
            provider: Some(AccountProvider::Blink),
            wallet_kind: Some(WalletKind::Usd),
            wallet_id: Some("blink_usd_wallet_round_trip".to_string()),
            provider_payment_hash: Some("blink_provider_hash_round_trip".to_string()),
            payment_hash: "round_trip_blink_hash".to_string(),
            user_pubkey: String::new(),
            invoice: "lnbc1roundtripblink".to_string(),
            preimage: None,
            invoice_expiry: now.saturating_add(120_000),
            created_at: now,
            updated_at: now,
            domain: Some("round-trip.example.com".to_string()),
            amount_received_sat: None,
        };

        db.upsert_invoice(&spark_invoice).await.unwrap();
        db.upsert_invoice(&blink_invoice).await.unwrap();

        let stored_spark = db
            .get_invoice_by_payment_hash("round_trip_spark_hash")
            .await
            .unwrap()
            .expect("Spark invoice should round-trip");
        assert_eq!(stored_spark.provider, Some(AccountProvider::Spark));
        assert_eq!(stored_spark.wallet_kind, Some(WalletKind::Btc));
        assert!(stored_spark.wallet_id.is_none());
        assert!(stored_spark.provider_payment_hash.is_none());
        assert_eq!(
            stored_spark.account_id.as_deref(),
            Some("acct_round_trip_spark")
        );
        assert_eq!(
            stored_spark.domain.as_deref(),
            Some("round-trip.example.com")
        );
        assert_eq!(stored_spark.payment_hash, "round_trip_spark_hash");
        assert_eq!(stored_spark.invoice, "lnbc1roundtripspark");
        assert_eq!(stored_spark.invoice_expiry, spark_invoice.invoice_expiry);

        let stored_blink = db
            .get_invoice_by_payment_hash("round_trip_blink_hash")
            .await
            .unwrap()
            .expect("Blink invoice should round-trip");
        assert_eq!(stored_blink.provider, Some(AccountProvider::Blink));
        assert_eq!(stored_blink.wallet_kind, Some(WalletKind::Usd));
        assert_eq!(
            stored_blink.wallet_id.as_deref(),
            Some("blink_usd_wallet_round_trip")
        );
        assert_eq!(
            stored_blink.provider_payment_hash.as_deref(),
            Some("blink_provider_hash_round_trip")
        );
        assert_eq!(
            stored_blink.account_id.as_deref(),
            Some("acct_round_trip_blink")
        );
        assert_eq!(
            stored_blink.domain.as_deref(),
            Some("round-trip.example.com")
        );
        assert_eq!(stored_blink.payment_hash, "round_trip_blink_hash");
        assert_eq!(stored_blink.invoice, "lnbc1roundtripblink");
        assert_eq!(stored_blink.invoice_expiry, blink_invoice.invoice_expiry);
    }

    pub async fn invoice_ownership_fields_round_trip<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // TEST-02/LNURL-05: provide an explicit release-gate test name for the
        // provider/account/domain/wallet invoice ownership parity assertions.
        invoice_provider_metadata_round_trips(db).await;
    }

    pub async fn metadata_account_id_round_trips_and_legacy_rows_remain_none<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // DATA-02/D-13/D-16: metadata remains callable by legacy Spark pubkey,
        // while provider-neutral ownership is exposed when side-effect rows carry it.
        let account_id = generate_account_id(AccountProvider::Spark);
        let pubkey = "spark_metadata_account_pubkey".to_string();
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(account_id.clone()),
            pubkey: pubkey.clone(),
            identifier: NewAccountIdentifier {
                domain: "metadata-account.example.com".to_string(),
                identifier: "mallory".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "metadata account".to_string(),
            },
        })
        .await
        .unwrap();

        let now = crate::time::now_millis();
        let owned_hash = "metadata_account_owned_hash".to_string();
        db.upsert_invoice(&Invoice {
            account_id: Some(account_id.clone()),
            provider: None,
            wallet_kind: None,
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash: owned_hash.clone(),
            user_pubkey: pubkey.clone(),
            invoice: "lnbc1metadataowned".to_string(),
            preimage: Some("metadata_owned_preimage".to_string()),
            invoice_expiry: i64::MAX,
            created_at: now,
            updated_at: now,
            domain: Some("metadata-account.example.com".to_string()),
            amount_received_sat: None,
        })
        .await
        .unwrap();
        db.upsert_zap(&Zap {
            account_id: Some(account_id.clone()),
            payment_hash: owned_hash.clone(),
            zap_request: r#"{"kind":9734}"#.to_string(),
            zap_event: None,
            user_pubkey: pubkey.clone(),
            invoice_expiry: i64::MAX,
            updated_at: now,
            is_user_nostr_key: false,
        })
        .await
        .unwrap();
        db.insert_lnurl_sender_comment(&LnurlSenderComment {
            account_id: Some(account_id.clone()),
            comment: "provider-neutral metadata".to_string(),
            payment_hash: owned_hash.clone(),
            user_pubkey: pubkey.clone(),
            updated_at: now,
        })
        .await
        .unwrap();

        let legacy_hash = "metadata_account_legacy_hash".to_string();
        db.upsert_invoice(&Invoice {
            account_id: None,
            provider: None,
            wallet_kind: None,
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash: legacy_hash.clone(),
            user_pubkey: pubkey.clone(),
            invoice: "lnbc1metadatalegacy".to_string(),
            preimage: None,
            invoice_expiry: i64::MAX,
            created_at: now.saturating_add(1),
            updated_at: now.saturating_add(1),
            domain: Some("metadata-account.example.com".to_string()),
            amount_received_sat: None,
        })
        .await
        .unwrap();

        let metadata = db
            .get_metadata_by_pubkey(&pubkey, 0, 10, None)
            .await
            .unwrap();
        let owned = metadata
            .iter()
            .find(|item| item.payment_hash == owned_hash)
            .expect("owned metadata row should be returned");
        assert_eq!(owned.account_id.as_deref(), Some(account_id.as_str()));
        assert_eq!(
            owned.sender_comment.as_deref(),
            Some("provider-neutral metadata")
        );

        let legacy = metadata
            .iter()
            .find(|item| item.payment_hash == legacy_hash)
            .expect("legacy metadata row should be returned");
        assert!(legacy.account_id.is_none());
    }

    #[allow(clippy::too_many_lines)]
    pub async fn metadata_webhook_join_uses_provider_neutral_owner<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // TEST-02/T-09-02-02: metadata and webhook joins should derive
        // ownership context from provider-neutral account identifiers while the
        // external-facing address remains the public lightning address.
        let account_id = generate_account_id(AccountProvider::Blink);
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some(account_id.clone()),
            blink_account_id: "blink_test02_join_account".to_string(),
            btc_wallet_id: "blink_test02_join_btc".to_string(),
            usd_wallet_id: "blink_test02_join_usd".to_string(),
            default_wallet: WalletKind::Btc,
            identifiers: vec![
                NewAccountIdentifier {
                    domain: "test02-join.example.com".to_string(),
                    identifier: "webhookjoin".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "Webhook join owner".to_string(),
                },
                NewAccountIdentifier {
                    domain: "test02-join.example.com".to_string(),
                    identifier: "+573005871213".to_string(),
                    identifier_kind: AccountIdentifierKind::Phone,
                    description: "Webhook phone owner".to_string(),
                },
            ],
        })
        .await
        .unwrap();

        let now = crate::time::now_millis();
        let payment_hash = "test02_join_payment_hash".to_string();
        db.upsert_invoice(&Invoice {
            account_id: Some(account_id.clone()),
            provider: Some(AccountProvider::Blink),
            wallet_kind: Some(WalletKind::Btc),
            wallet_id: Some("blink_test02_join_btc".to_string()),
            provider_payment_hash: Some("blink_test02_join_provider_hash".to_string()),
            payment_hash: payment_hash.clone(),
            user_pubkey: "legacy_join_pubkey".to_string(),
            invoice: "lnbc1test02join".to_string(),
            preimage: Some("test02_join_preimage".to_string()),
            invoice_expiry: i64::MAX,
            created_at: now,
            updated_at: now,
            domain: Some("test02-join.example.com".to_string()),
            amount_received_sat: Some(42),
        })
        .await
        .unwrap();
        db.upsert_zap(&Zap {
            account_id: Some(account_id.clone()),
            payment_hash: payment_hash.clone(),
            zap_request: r#"{"kind":9734}"#.to_string(),
            zap_event: Some(r#"{"kind":9735}"#.to_string()),
            user_pubkey: "legacy_join_pubkey".to_string(),
            invoice_expiry: i64::MAX,
            updated_at: now,
            is_user_nostr_key: false,
        })
        .await
        .unwrap();
        db.insert_lnurl_sender_comment(&LnurlSenderComment {
            account_id: Some(account_id.clone()),
            comment: "join sender comment".to_string(),
            payment_hash: payment_hash.clone(),
            user_pubkey: "legacy_join_pubkey".to_string(),
            updated_at: now,
        })
        .await
        .unwrap();

        let metadata = db
            .get_metadata_by_pubkey("legacy_join_pubkey", 0, 10, None)
            .await
            .unwrap();
        let item = metadata
            .iter()
            .find(|item| item.payment_hash == payment_hash)
            .expect("metadata join should include the provider-neutral invoice");
        assert_eq!(item.account_id.as_deref(), Some(account_id.as_str()));
        assert_eq!(item.sender_comment.as_deref(), Some("join sender comment"));

        let payloads = db
            .get_webhook_payloads(std::slice::from_ref(&payment_hash))
            .await
            .unwrap();
        let payload = payloads
            .first()
            .expect("paid provider-neutral invoice should build webhook payload data");
        assert_eq!(payload.account_id.as_deref(), Some(account_id.as_str()));
        assert_eq!(payload.domain, "test02-join.example.com");
        assert_eq!(payload.payment_hash, payment_hash);
        assert_eq!(payload.preimage, "test02_join_preimage");
        assert_eq!(payload.amount_received_sat, Some(42));
        assert_eq!(
            payload.lightning_address.as_deref(),
            Some("webhookjoin@test02-join.example.com")
        );
        assert_ne!(
            payload.lightning_address.as_deref(),
            payload.account_id.as_deref(),
            "external lightning address must not be the internal account id"
        );
        assert_eq!(
            payload.sender_comment.as_deref(),
            Some("join sender comment")
        );
    }

    #[allow(clippy::too_many_lines)]
    pub async fn delete_spark_registration_preserves_account_with_side_effect_ownership<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // DATA-05/DATA-02: unregistering Spark deletes only active identifier
        // ownership and the legacy user row. Provider-neutral account rows are
        // historical ownership anchors for invoices, zaps, and sender comments.
        let account_id = generate_account_id(AccountProvider::Spark);
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(account_id.clone()),
            pubkey: "spark_delete_preserve_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "delete-preserve.example.com".to_string(),
                identifier: "heidi".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "delete preserve".to_string(),
            },
        })
        .await
        .unwrap();

        let now = crate::time::now_millis();
        let payment_hash = "delete_preserve_hash".to_string();
        db.upsert_invoice(&Invoice {
            account_id: Some(account_id.clone()),
            provider: None,
            wallet_kind: None,
            wallet_id: None,
            provider_payment_hash: None,
            payment_hash: payment_hash.clone(),
            user_pubkey: "spark_delete_preserve_pubkey".to_string(),
            invoice: "lnbc1deletepreserve".to_string(),
            preimage: Some("delete_preserve_preimage".to_string()),
            invoice_expiry: i64::MAX,
            created_at: now,
            updated_at: now,
            domain: Some("delete-preserve.example.com".to_string()),
            amount_received_sat: None,
        })
        .await
        .unwrap();
        db.upsert_zap(&Zap {
            account_id: Some(account_id.clone()),
            payment_hash: payment_hash.clone(),
            zap_request: r#"{"kind":9734}"#.to_string(),
            zap_event: None,
            user_pubkey: "spark_delete_preserve_pubkey".to_string(),
            invoice_expiry: i64::MAX,
            updated_at: now,
            is_user_nostr_key: false,
        })
        .await
        .unwrap();
        db.insert_lnurl_sender_comment(&LnurlSenderComment {
            account_id: Some(account_id.clone()),
            comment: "historical ownership".to_string(),
            payment_hash: payment_hash.clone(),
            user_pubkey: "spark_delete_preserve_pubkey".to_string(),
            updated_at: now,
        })
        .await
        .unwrap();

        db.delete_spark_registration(
            "delete-preserve.example.com",
            "spark_delete_preserve_pubkey",
            "heidi",
        )
        .await
        .unwrap();

        assert!(
            db.get_user_by_pubkey(
                "delete-preserve.example.com",
                "spark_delete_preserve_pubkey"
            )
            .await
            .unwrap()
            .is_none(),
            "legacy users row should be removed"
        );
        assert!(
            db.resolve_recipient_by_identifier("delete-preserve.example.com", "heidi")
                .await
                .unwrap()
                .is_none(),
            "active identifier ownership should be removed"
        );

        let account = db
            .get_account_by_id(&account_id)
            .await
            .unwrap()
            .expect("historical account row should remain");
        assert_eq!(account.provider, AccountProvider::Spark);
        let by_pubkey = db
            .get_account_by_spark_pubkey("spark_delete_preserve_pubkey")
            .await
            .unwrap()
            .expect("Spark child row should remain addressable");
        assert_eq!(by_pubkey.account_id, account_id);

        let invoice = db
            .get_invoice_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("invoice should remain");
        assert_eq!(invoice.account_id.as_deref(), Some(account_id.as_str()));
        let zap = db
            .get_zap_by_payment_hash(&payment_hash)
            .await
            .unwrap()
            .expect("zap should remain");
        assert_eq!(zap.account_id.as_deref(), Some(account_id.as_str()));
        let payloads = db
            .get_webhook_payloads(std::slice::from_ref(&payment_hash))
            .await
            .unwrap();
        let payload = payloads
            .first()
            .expect("sender comment should remain available through webhook payload");
        assert_eq!(payload.account_id.as_deref(), Some(account_id.as_str()));
        assert_eq!(
            payload.sender_comment.as_deref(),
            Some("historical ownership")
        );
    }

    pub async fn post_transfer_lookup_and_metadata_join_consistency<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        let source_account_id = generate_account_id(AccountProvider::Blink);
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some(source_account_id.clone()),
            blink_account_id: "blink_consistency_account".to_string(),
            btc_wallet_id: "blink_consistency_btc".to_string(),
            usd_wallet_id: "blink_consistency_usd".to_string(),
            default_wallet: WalletKind::Usd,
            identifiers: vec![
                NewAccountIdentifier {
                    domain: "post-transfer-consistency.example.com".to_string(),
                    identifier: "moving".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "moving before transfer".to_string(),
                },
                NewAccountIdentifier {
                    domain: "post-transfer-consistency.example.com".to_string(),
                    identifier: "stays".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "stays with Blink".to_string(),
                },
            ],
        })
        .await
        .unwrap();

        db.transfer_blink_identifier_to_spark(&BlinkToSparkIdentifierTransfer {
            domain: "post-transfer-consistency.example.com".to_string(),
            identifier: "moving".to_string(),
            source_account_id: source_account_id.clone(),
            destination_spark_pubkey: "spark_consistency_destination".to_string(),
            description: "moving after transfer".to_string(),
        })
        .await
        .unwrap();

        let moved = db
            .resolve_recipient_by_identifier("post-transfer-consistency.example.com", "moving")
            .await
            .unwrap()
            .expect("moved identifier should resolve");
        assert_eq!(moved.provider, AccountProvider::Spark);
        assert_eq!(
            moved.spark_pubkey.as_deref(),
            Some("spark_consistency_destination")
        );
        assert_eq!(moved.description, "moving after transfer");

        let stayed = db
            .resolve_recipient_by_identifier("post-transfer-consistency.example.com", "stays")
            .await
            .unwrap()
            .expect("untouched identifier should still resolve");
        assert_eq!(stayed.provider, AccountProvider::Blink);
        assert_eq!(stayed.account_id, source_account_id);
        assert_eq!(stayed.description, "stays with Blink");
        assert_eq!(stayed.default_wallet, Some(WalletKind::Usd));
    }

    pub async fn atomic_transfer_preserves_historical_invoice_owner<DB>(db: &DB)
    where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // TEST-02/T-09-02-03: expose the atomic transfer/history invariant with
        // the release-gate artifact name while reusing the detailed shared test.
        transfer_blink_identifier_to_spark_preserves_historical_blink_invoice_owner(db).await;
    }

    pub async fn create_blink_account_rejects_existing_spark_account_id_with_invalid_provider<DB>(
        db: &DB,
    ) where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // DATA-06/D-18: caller-supplied account ids already owned by Spark must
        // return the provider-neutral InvalidProvider error, not a backend
        // constraint fallback.
        let account_id = generate_account_id(AccountProvider::Spark);
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(account_id.clone()),
            pubkey: "spark_supplied_id_collision_pubkey".to_string(),
            identifier: NewAccountIdentifier {
                domain: "supplied-spark.example.com".to_string(),
                identifier: "ivan".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "spark owner".to_string(),
            },
        })
        .await
        .unwrap();

        let result = db
            .create_blink_account(&NewBlinkAccount {
                account_id: Some(account_id),
                blink_account_id: "blink_supplied_spark_collision".to_string(),
                btc_wallet_id: "blink_supplied_spark_btc".to_string(),
                usd_wallet_id: "blink_supplied_spark_usd".to_string(),
                default_wallet: WalletKind::Btc,
                identifiers: vec![NewAccountIdentifier {
                    domain: "supplied-spark.example.com".to_string(),
                    identifier: "judy".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "blink claimant".to_string(),
                }],
            })
            .await;

        assert!(matches!(result, Err(LnurlRepositoryError::InvalidProvider)));
    }

    pub async fn create_blink_account_rejects_existing_inconsistent_blink_account_id_with_invalid_ownership<
        DB,
    >(
        db: &DB,
    ) where
        DB: LnurlRepository + Clone + Send + Sync + 'static,
    {
        // DATA-06/D-18: an existing Blink account id with a different Blink
        // natural key is an ownership mismatch and must not fall through to a
        // unique constraint or generic storage error.
        let account_id = generate_account_id(AccountProvider::Blink);
        db.create_blink_account(&NewBlinkAccount {
            account_id: Some(account_id.clone()),
            blink_account_id: "blink_existing_owner".to_string(),
            btc_wallet_id: "blink_existing_owner_btc".to_string(),
            usd_wallet_id: "blink_existing_owner_usd".to_string(),
            default_wallet: WalletKind::Btc,
            identifiers: vec![NewAccountIdentifier {
                domain: "inconsistent-blink.example.com".to_string(),
                identifier: "kate".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "first blink owner".to_string(),
            }],
        })
        .await
        .unwrap();

        let result = db
            .create_blink_account(&NewBlinkAccount {
                account_id: Some(account_id),
                blink_account_id: "blink_different_owner".to_string(),
                btc_wallet_id: "blink_different_owner_btc".to_string(),
                usd_wallet_id: "blink_different_owner_usd".to_string(),
                default_wallet: WalletKind::Usd,
                identifiers: vec![NewAccountIdentifier {
                    domain: "inconsistent-blink.example.com".to_string(),
                    identifier: "lara".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "second blink owner".to_string(),
                }],
            })
            .await;

        assert!(matches!(
            result,
            Err(LnurlRepositoryError::InvalidOwnership)
        ));
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
