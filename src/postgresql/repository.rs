use crate::models::ListMetadataMetadata;
use sqlx::{PgPool, Row};

use crate::repository::{
    Account, AccountIdentifierKind, AccountProvider, IdentifierTransfer, Invoice,
    LnurlSenderComment, NewBlinkAccount, NewSparkRegistration, PendingZapReceipt,
    ResolvedRecipient, WalletKind, WebhookPayloadData, generate_account_id,
};
use crate::webhooks::repository::{
    NewWebhookDelivery, WebhookConfig, WebhookDelivery, WebhookRepositoryError,
};
use crate::zap::Zap;
use crate::{
    repository::LnurlRepositoryError,
    time::{now, now_millis},
    user::User,
};

#[derive(Clone)]
pub struct LnurlRepository {
    pool: PgPool,
}

impl LnurlRepository {
    pub fn new(pool: PgPool) -> Self {
        LnurlRepository { pool }
    }
}

fn map_resolved_recipient(
    row: &sqlx::postgres::PgRow,
) -> Result<ResolvedRecipient, LnurlRepositoryError> {
    let provider = AccountProvider::from_database_value(row.try_get("provider")?)?;
    let identifier_kind =
        AccountIdentifierKind::from_database_value(row.try_get("identifier_kind")?)?;
    let spark_pubkey: Option<String> = row.try_get("spark_pubkey")?;
    let blink_account_id: Option<String> = row.try_get("blink_account_id")?;
    let btc_wallet_id: Option<String> = row.try_get("btc_wallet_id")?;
    let usd_wallet_id: Option<String> = row.try_get("usd_wallet_id")?;
    let default_wallet = row
        .try_get::<Option<String>, _>("default_wallet")?
        .map(|wallet| WalletKind::from_database_value(&wallet))
        .transpose()?;

    match provider {
        AccountProvider::Spark => {
            if spark_pubkey.is_none()
                || blink_account_id.is_some()
                || btc_wallet_id.is_some()
                || usd_wallet_id.is_some()
                || default_wallet.is_some()
            {
                return Err(LnurlRepositoryError::InvalidOwnership);
            }
        }
        AccountProvider::Blink => {
            if spark_pubkey.is_some()
                || blink_account_id.is_none()
                || btc_wallet_id.is_none()
                || usd_wallet_id.is_none()
                || default_wallet.is_none()
            {
                return Err(LnurlRepositoryError::InvalidOwnership);
            }
        }
    }

    Ok(ResolvedRecipient {
        account_id: row.try_get("account_id")?,
        provider,
        domain: row.try_get("domain")?,
        identifier: row.try_get("identifier")?,
        identifier_kind,
        description: row.try_get("description")?,
        spark_pubkey,
        blink_account_id,
        btc_wallet_id,
        usd_wallet_id,
        default_wallet,
    })
}

fn map_account(row: &sqlx::postgres::PgRow) -> Result<Account, LnurlRepositoryError> {
    Ok(Account {
        account_id: row.try_get("account_id")?,
        provider: AccountProvider::from_database_value(row.try_get("provider")?)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

#[async_trait::async_trait]
#[allow(clippy::too_many_lines)]
impl crate::repository::LnurlRepository for LnurlRepository {
    async fn delete_user(&self, domain: &str, pubkey: &str) -> Result<(), LnurlRepositoryError> {
        sqlx::query("DELETE FROM users WHERE domain = $1 AND pubkey = $2")
            .bind(domain)
            .bind(pubkey)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_user_by_name(
        &self,
        domain: &str,
        name: &str,
    ) -> Result<Option<User>, LnurlRepositoryError> {
        let maybe_user = sqlx::query(
            "SELECT pubkey, name, description
             FROM users
             WHERE domain = $1 AND name = $2",
        )
        .bind(domain)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| {
            Ok::<_, sqlx::Error>(User {
                domain: domain.to_string(),
                pubkey: row.try_get(0)?,
                name: row.try_get(1)?,
                description: row.try_get(2)?,
            })
        })
        .transpose()?;
        Ok(maybe_user)
    }

    async fn get_user_by_pubkey(
        &self,
        domain: &str,
        pubkey: &str,
    ) -> Result<Option<User>, LnurlRepositoryError> {
        let maybe_user = sqlx::query(
            "SELECT pubkey, name, description
                FROM users
                WHERE domain = $1 AND pubkey = $2",
        )
        .bind(domain)
        .bind(pubkey)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| {
            Ok::<_, sqlx::Error>(User {
                domain: domain.to_string(),
                pubkey: row.try_get(0)?,
                name: row.try_get(1)?,
                description: row.try_get(2)?,
            })
        })
        .transpose()?;
        Ok(maybe_user)
    }

    async fn upsert_user(&self, user: &User) -> Result<(), LnurlRepositoryError> {
        sqlx::query(
            "INSERT INTO users (domain, pubkey, name, description, updated_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(domain, pubkey) DO UPDATE
             SET name = excluded.name
             ,   description = excluded.description
             ,   updated_at = excluded.updated_at",
        )
        .bind(&user.domain)
        .bind(&user.pubkey)
        .bind(&user.name)
        .bind(&user.description)
        .bind(now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn resolve_recipient_by_identifier(
        &self,
        domain: &str,
        identifier: &str,
    ) -> Result<Option<ResolvedRecipient>, LnurlRepositoryError> {
        sqlx::query(
            "SELECT a.account_id AS account_id
             ,      a.provider AS provider
             ,      ai.domain AS domain
             ,      ai.identifier AS identifier
             ,      ai.identifier_kind AS identifier_kind
             ,      ai.description AS description
             ,      s.pubkey AS spark_pubkey
             ,      b.blink_account_id AS blink_account_id
             ,      b.btc_wallet_id AS btc_wallet_id
             ,      b.usd_wallet_id AS usd_wallet_id
             ,      b.default_wallet AS default_wallet
             FROM account_identifiers ai
             JOIN accounts a ON a.account_id = ai.account_id
             LEFT JOIN spark_accounts s ON s.account_id = a.account_id
             LEFT JOIN blink_accounts b ON b.account_id = a.account_id
             WHERE ai.domain = $1 AND ai.identifier = $2",
        )
        .bind(domain)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| map_resolved_recipient(&row))
        .transpose()
    }

    async fn get_account_by_id(
        &self,
        account_id: &str,
    ) -> Result<Option<Account>, LnurlRepositoryError> {
        sqlx::query(
            "SELECT account_id, provider, created_at, updated_at
             FROM accounts
             WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| map_account(&row))
        .transpose()
    }

    async fn get_account_by_spark_pubkey(
        &self,
        pubkey: &str,
    ) -> Result<Option<Account>, LnurlRepositoryError> {
        sqlx::query(
            "SELECT a.account_id, a.provider, a.created_at, a.updated_at
             FROM spark_accounts s
             JOIN accounts a ON a.account_id = s.account_id
             WHERE s.pubkey = $1",
        )
        .bind(pubkey)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| map_account(&row))
        .transpose()
    }

    async fn upsert_spark_registration(
        &self,
        registration: &NewSparkRegistration,
    ) -> Result<(), LnurlRepositoryError> {
        registration.validate()?;
        let now = now();
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LnurlRepositoryError::General(e.into()))?;

        let account_id = if let Some(account_id) = &registration.account_id {
            account_id.clone()
        } else if let Some((account_id,)) = sqlx::query_as::<_, (String,)>(
            "SELECT account_id FROM spark_accounts WHERE pubkey = $1",
        )
        .bind(&registration.pubkey)
        .fetch_optional(&mut *tx)
        .await?
        {
            account_id
        } else {
            generate_account_id(AccountProvider::Spark)
        };

        if let Some((provider,)) =
            sqlx::query_as::<_, (String,)>("SELECT provider FROM accounts WHERE account_id = $1")
                .bind(&account_id)
                .fetch_optional(&mut *tx)
                .await?
            && AccountProvider::from_database_value(&provider)? != AccountProvider::Spark
        {
            return Err(LnurlRepositoryError::InvalidProvider);
        }

        if let Some((owner_account_id,)) = sqlx::query_as::<_, (String,)>(
            "SELECT account_id FROM account_identifiers WHERE domain = $1 AND identifier = $2",
        )
        .bind(&registration.identifier.domain)
        .bind(&registration.identifier.identifier)
        .fetch_optional(&mut *tx)
        .await?
            && owner_account_id != account_id
        {
            return Err(LnurlRepositoryError::IdentifierConflict);
        }

        if let Some((owner_account_id,)) = sqlx::query_as::<_, (String,)>(
            "SELECT account_id FROM spark_accounts WHERE pubkey = $1",
        )
        .bind(&registration.pubkey)
        .fetch_optional(&mut *tx)
        .await?
            && owner_account_id != account_id
        {
            return Err(LnurlRepositoryError::InvalidOwnership);
        }

        sqlx::query(
            "INSERT INTO accounts (account_id, provider, created_at, updated_at)
             VALUES ($1, $2, $3, $3)
             ON CONFLICT(account_id) DO UPDATE
             SET provider = excluded.provider
             ,   updated_at = excluded.updated_at",
        )
        .bind(&account_id)
        .bind(AccountProvider::Spark.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO spark_accounts (account_id, pubkey, created_at, updated_at)
             VALUES ($1, $2, $3, $3)
             ON CONFLICT(account_id) DO UPDATE
             SET pubkey = excluded.pubkey
             ,   updated_at = excluded.updated_at",
        )
        .bind(&account_id)
        .bind(&registration.pubkey)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO account_identifiers (account_id, domain, identifier, identifier_kind, description, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $6)
             ON CONFLICT(account_id, domain, identifier) DO UPDATE
             SET identifier_kind = excluded.identifier_kind
             ,   description = excluded.description
             ,   updated_at = excluded.updated_at",
        )
        .bind(&account_id)
        .bind(&registration.identifier.domain)
        .bind(&registration.identifier.identifier)
        .bind(registration.identifier.identifier_kind.as_str())
        .bind(&registration.identifier.description)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO users (domain, pubkey, name, description, updated_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(domain, pubkey) DO UPDATE
             SET name = excluded.name
             ,   description = excluded.description
             ,   updated_at = excluded.updated_at",
        )
        .bind(&registration.identifier.domain)
        .bind(&registration.pubkey)
        .bind(&registration.identifier.identifier)
        .bind(&registration.identifier.description)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit()
            .await
            .map_err(|e| LnurlRepositoryError::General(e.into()))?;
        Ok(())
    }

    async fn create_blink_account(
        &self,
        account: &NewBlinkAccount,
    ) -> Result<(), LnurlRepositoryError> {
        let account_id = account
            .account_id
            .clone()
            .unwrap_or_else(|| generate_account_id(AccountProvider::Blink));
        let now = now();
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LnurlRepositoryError::General(e.into()))?;

        if let Some((provider,)) =
            sqlx::query_as::<_, (String,)>("SELECT provider FROM accounts WHERE account_id = $1")
                .bind(&account_id)
                .fetch_optional(&mut *tx)
                .await?
        {
            if AccountProvider::from_database_value(&provider)? != AccountProvider::Blink {
                return Err(LnurlRepositoryError::InvalidProvider);
            }

            let existing = sqlx::query_as::<_, (String, String, String, String)>(
                "SELECT blink_account_id, btc_wallet_id, usd_wallet_id, default_wallet
                 FROM blink_accounts
                 WHERE account_id = $1",
            )
            .bind(&account_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((blink_account_id, btc_wallet_id, usd_wallet_id, default_wallet)) = existing
            else {
                return Err(LnurlRepositoryError::InvalidOwnership);
            };
            if blink_account_id != account.blink_account_id
                || btc_wallet_id != account.btc_wallet_id
                || usd_wallet_id != account.usd_wallet_id
                || default_wallet != account.default_wallet.as_str()
            {
                return Err(LnurlRepositoryError::InvalidOwnership);
            }
            return Err(LnurlRepositoryError::BlinkAccountExists);
        }

        if sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM blink_accounts WHERE blink_account_id = $1",
        )
        .bind(&account.blink_account_id)
        .fetch_one(&mut *tx)
        .await?
            > 0
        {
            return Err(LnurlRepositoryError::BlinkAccountExists);
        }

        for identifier in &account.identifiers {
            if sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM account_identifiers WHERE domain = $1 AND identifier = $2",
            )
            .bind(&identifier.domain)
            .bind(&identifier.identifier)
            .fetch_one(&mut *tx)
            .await?
                > 0
            {
                return Err(LnurlRepositoryError::IdentifierConflict);
            }
        }

        sqlx::query(
            "INSERT INTO accounts (account_id, provider, created_at, updated_at)
             VALUES ($1, $2, $3, $3)",
        )
        .bind(&account_id)
        .bind(AccountProvider::Blink.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO blink_accounts (account_id, blink_account_id, btc_wallet_id, usd_wallet_id, default_wallet, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $6)",
        )
        .bind(&account_id)
        .bind(&account.blink_account_id)
        .bind(&account.btc_wallet_id)
        .bind(&account.usd_wallet_id)
        .bind(account.default_wallet.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await?;

        for identifier in &account.identifiers {
            sqlx::query(
                "INSERT INTO account_identifiers (account_id, domain, identifier, identifier_kind, description, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $6)",
            )
            .bind(&account_id)
            .bind(&identifier.domain)
            .bind(&identifier.identifier)
            .bind(identifier.identifier_kind.as_str())
            .bind(&identifier.description)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit()
            .await
            .map_err(|e| LnurlRepositoryError::General(e.into()))?;
        Ok(())
    }

    async fn delete_spark_registration(
        &self,
        domain: &str,
        pubkey: &str,
    ) -> Result<(), LnurlRepositoryError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LnurlRepositoryError::General(e.into()))?;

        let account_id: Option<String> =
            sqlx::query_scalar("SELECT account_id FROM spark_accounts WHERE pubkey = $1")
                .bind(pubkey)
                .fetch_optional(&mut *tx)
                .await?;

        if let Some(account_id) = account_id {
            sqlx::query("DELETE FROM account_identifiers WHERE account_id = $1 AND domain = $2")
                .bind(&account_id)
                .bind(domain)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM users WHERE domain = $1 AND pubkey = $2")
                .bind(domain)
                .bind(pubkey)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit()
            .await
            .map_err(|e| LnurlRepositoryError::General(e.into()))?;
        Ok(())
    }

    async fn transfer_identifier(
        &self,
        transfer: &IdentifierTransfer,
    ) -> Result<(), LnurlRepositoryError> {
        let now = now();
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LnurlRepositoryError::General(e.into()))?;

        let source_account_id: Option<String> = sqlx::query_scalar(
            "SELECT account_id FROM account_identifiers WHERE domain = $1 AND identifier = $2",
        )
        .bind(&transfer.domain)
        .bind(&transfer.identifier)
        .fetch_optional(&mut *tx)
        .await?;

        if source_account_id.as_deref() != Some(transfer.source_account_id.as_str()) {
            return Err(LnurlRepositoryError::SourceNotOwner);
        }

        if sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM accounts WHERE account_id = $1")
            .bind(&transfer.destination_account_id)
            .fetch_one(&mut *tx)
            .await?
            == 0
        {
            return Err(LnurlRepositoryError::AccountNotFound);
        }

        sqlx::query(
            "UPDATE account_identifiers
             SET account_id = $3
             ,   description = $4
             ,   updated_at = $5
             WHERE domain = $1 AND identifier = $2 AND account_id = $6",
        )
        .bind(&transfer.domain)
        .bind(&transfer.identifier)
        .bind(&transfer.destination_account_id)
        .bind(&transfer.description)
        .bind(now)
        .bind(&transfer.source_account_id)
        .execute(&mut *tx)
        .await?;

        tx.commit()
            .await
            .map_err(|e| LnurlRepositoryError::General(e.into()))?;
        Ok(())
    }

    async fn transfer_username(
        &self,
        domain: &str,
        from_pubkey: &str,
        to_pubkey: &str,
        username: &str,
        description: &str,
    ) -> Result<(), LnurlRepositoryError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LnurlRepositoryError::General(e.into()))?;

        let source_name: Option<(String,)> =
            sqlx::query_as("DELETE FROM users WHERE domain = $1 AND pubkey = $2 RETURNING name")
                .bind(domain)
                .bind(from_pubkey)
                .fetch_optional(&mut *tx)
                .await?;
        match source_name {
            Some((name,)) if name == username => {}
            // Source pubkey doesn't currently own this username. The tx is
            // rolled back on drop, so the speculative DELETE is undone.
            _ => return Err(LnurlRepositoryError::SourceNotOwner),
        }

        sqlx::query(
            "INSERT INTO users (domain, pubkey, name, description, updated_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(domain, pubkey) DO UPDATE
             SET name = excluded.name
             ,   description = excluded.description
             ,   updated_at = excluded.updated_at",
        )
        .bind(domain)
        .bind(to_pubkey)
        .bind(username)
        .bind(description)
        .bind(now())
        .execute(&mut *tx)
        .await?;

        tx.commit()
            .await
            .map_err(|e| LnurlRepositoryError::General(e.into()))?;
        Ok(())
    }

    async fn upsert_zap(&self, zap: &Zap) -> Result<(), LnurlRepositoryError> {
        sqlx::query(
            "INSERT INTO zaps (payment_hash, zap_request, zap_event
            , user_pubkey, invoice_expiry, updated_at, is_user_nostr_key, account_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
              ON CONFLICT(payment_hash) DO UPDATE
              SET zap_request = excluded.zap_request
              ,   zap_event = excluded.zap_event
              ,   user_pubkey = excluded.user_pubkey
              ,   invoice_expiry = excluded.invoice_expiry
              ,   updated_at = excluded.updated_at
              ,   is_user_nostr_key = excluded.is_user_nostr_key
              ,   account_id = COALESCE(excluded.account_id, zaps.account_id)",
        )
        .bind(&zap.payment_hash)
        .bind(&zap.zap_request)
        .bind(&zap.zap_event)
        .bind(&zap.user_pubkey)
        .bind(zap.invoice_expiry)
        .bind(zap.updated_at)
        .bind(zap.is_user_nostr_key)
        .bind(zap.account_id.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_zap_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<Option<Zap>, LnurlRepositoryError> {
        let maybe_zap = sqlx::query(
            "SELECT payment_hash, zap_request, zap_event, user_pubkey
            , invoice_expiry, updated_at, is_user_nostr_key, account_id
             FROM zaps
             WHERE payment_hash = $1",
        )
        .bind(payment_hash)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| {
            Ok::<_, sqlx::Error>(Zap {
                payment_hash: row.try_get(0)?,
                zap_request: row.try_get(1)?,
                zap_event: row.try_get(2)?,
                user_pubkey: row.try_get(3)?,
                invoice_expiry: row.try_get(4)?,
                updated_at: row.try_get(5)?,
                is_user_nostr_key: row.try_get(6)?,
                account_id: row.try_get(7)?,
            })
        })
        .transpose()?;
        Ok(maybe_zap)
    }

    async fn insert_lnurl_sender_comment(
        &self,
        comment: &LnurlSenderComment,
    ) -> Result<(), LnurlRepositoryError> {
        sqlx::query(
            "INSERT INTO sender_comments (payment_hash, user_pubkey, sender_comment, updated_at, account_id)
             VALUES ($1, $2, $3, $4, $5)
              ON CONFLICT(payment_hash) DO UPDATE
              SET user_pubkey = excluded.user_pubkey
              ,   sender_comment = excluded.sender_comment
              ,   updated_at = excluded.updated_at
              ,   account_id = COALESCE(excluded.account_id, sender_comments.account_id)",
        )
        .bind(&comment.payment_hash)
        .bind(&comment.user_pubkey)
        .bind(&comment.comment)
        .bind(comment.updated_at)
        .bind(comment.account_id.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_metadata_by_pubkey(
        &self,
        pubkey: &str,
        offset: u32,
        limit: u32,
        updated_after: Option<i64>,
    ) -> Result<Vec<ListMetadataMetadata>, LnurlRepositoryError> {
        let updated_after = updated_after.unwrap_or(0);
        let rows = sqlx::query(
            "SELECT ph.payment_hash
             ,      sc.sender_comment
             ,      z.zap_request
             ,      z.zap_event
             ,      GREATEST(COALESCE(z.updated_at, 0), COALESCE(sc.updated_at, 0), COALESCE(i.updated_at, 0)) AS updated_at
             ,      i.preimage
             ,      COALESCE(i.account_id, z.account_id, sc.account_id) AS account_id
              FROM (
                 SELECT payment_hash FROM invoices WHERE user_pubkey = $1 AND updated_at > $4
                 UNION
                 SELECT payment_hash FROM zaps WHERE user_pubkey = $1 AND updated_at > $4
                 UNION
                 SELECT payment_hash FROM sender_comments WHERE user_pubkey = $1 AND updated_at > $4
             ) ph
             LEFT JOIN invoices i ON ph.payment_hash = i.payment_hash
             LEFT JOIN zaps z ON ph.payment_hash = z.payment_hash
             LEFT JOIN sender_comments sc ON ph.payment_hash = sc.payment_hash
             ORDER BY updated_at ASC
             OFFSET $2 LIMIT $3",
        )
        .bind(pubkey)
        .bind(i64::from(offset))
        .bind(i64::from(limit))
        .bind(updated_after)
        .fetch_all(&self.pool)
        .await?;
        let metadata = rows
            .into_iter()
            .map(|row| {
                Ok(ListMetadataMetadata {
                    payment_hash: row.try_get(0)?,
                    account_id: row.try_get(6)?,
                    sender_comment: row.try_get(1)?,
                    nostr_zap_request: row.try_get(2)?,
                    nostr_zap_receipt: row.try_get(3)?,
                    updated_at: row.try_get(4)?,
                    preimage: row.try_get(5)?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;
        Ok(metadata)
    }

    async fn list_domains(&self) -> Result<Vec<String>, LnurlRepositoryError> {
        let rows = sqlx::query("SELECT domain FROM allowed_domains")
            .fetch_all(&self.pool)
            .await?;

        let domains = rows
            .into_iter()
            .map(|row| row.try_get(0))
            .collect::<Result<Vec<String>, sqlx::Error>>()?;

        Ok(domains)
    }

    async fn add_domain(&self, domain: &str) -> Result<(), LnurlRepositoryError> {
        sqlx::query(
            "INSERT INTO allowed_domains (domain)
             VALUES ($1)
             ON CONFLICT(domain) DO NOTHING",
        )
        .bind(domain)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn filter_known_payment_hashes(
        &self,
        payment_hashes: &[String],
    ) -> Result<Vec<String>, LnurlRepositoryError> {
        if payment_hashes.is_empty() {
            return Ok(vec![]);
        }

        let known: Vec<String> = sqlx::query_scalar(
            "SELECT payment_hash FROM invoices WHERE payment_hash = ANY($1)
             UNION
             SELECT payment_hash FROM zaps WHERE payment_hash = ANY($1)
             UNION
             SELECT payment_hash FROM sender_comments WHERE payment_hash = ANY($1)",
        )
        .bind(payment_hashes)
        .fetch_all(&self.pool)
        .await?;
        Ok(known)
    }

    async fn upsert_invoice(&self, invoice: &Invoice) -> Result<(), LnurlRepositoryError> {
        sqlx::query(
            "INSERT INTO invoices (payment_hash, user_pubkey, invoice, preimage, invoice_expiry, created_at, updated_at, domain, amount_received_sat, account_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
              ON CONFLICT(payment_hash) DO UPDATE
              SET user_pubkey = excluded.user_pubkey
             ,   invoice = excluded.invoice
             ,   preimage = excluded.preimage
             ,   invoice_expiry = excluded.invoice_expiry
              ,   updated_at = excluded.updated_at
              ,   domain = excluded.domain
              ,   amount_received_sat = excluded.amount_received_sat
              ,   account_id = COALESCE(excluded.account_id, invoices.account_id)",
        )
        .bind(&invoice.payment_hash)
        .bind(&invoice.user_pubkey)
        .bind(&invoice.invoice)
        .bind(&invoice.preimage)
        .bind(invoice.invoice_expiry)
        .bind(invoice.created_at)
        .bind(invoice.updated_at)
        .bind(&invoice.domain)
        .bind(invoice.amount_received_sat)
        .bind(invoice.account_id.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn upsert_invoices_paid(
        &self,
        invoices: &[Invoice],
    ) -> Result<Vec<String>, LnurlRepositoryError> {
        if invoices.is_empty() {
            return Ok(vec![]);
        }
        let payment_hashes: Vec<&str> = invoices.iter().map(|i| i.payment_hash.as_str()).collect();
        let user_pubkeys: Vec<&str> = invoices.iter().map(|i| i.user_pubkey.as_str()).collect();
        let invoice_strs: Vec<&str> = invoices.iter().map(|i| i.invoice.as_str()).collect();
        let preimages: Vec<Option<&str>> = invoices.iter().map(|i| i.preimage.as_deref()).collect();
        let invoice_expiries: Vec<i64> = invoices.iter().map(|i| i.invoice_expiry).collect();
        let created_ats: Vec<i64> = invoices.iter().map(|i| i.created_at).collect();
        let updated_ats: Vec<i64> = invoices.iter().map(|i| i.updated_at).collect();
        let account_ids: Vec<Option<&str>> =
            invoices.iter().map(|i| i.account_id.as_deref()).collect();

        let rows = sqlx::query(
            "INSERT INTO invoices (payment_hash, user_pubkey, invoice, preimage, invoice_expiry, created_at, updated_at, account_id)
             SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::bigint[], $6::bigint[], $7::bigint[], $8::text[])
              ON CONFLICT(payment_hash) DO UPDATE
              SET preimage = excluded.preimage
              ,   updated_at = excluded.updated_at
              ,   account_id = COALESCE(excluded.account_id, invoices.account_id)
              WHERE invoices.user_pubkey = excluded.user_pubkey AND invoices.preimage IS NULL
              RETURNING payment_hash",
        )
        .bind(&payment_hashes)
        .bind(&user_pubkeys)
        .bind(&invoice_strs)
        .bind(&preimages)
        .bind(&invoice_expiries)
        .bind(&created_ats)
        .bind(&updated_ats)
        .bind(&account_ids)
        .fetch_all(&self.pool)
        .await?;

        let affected = rows
            .into_iter()
            .map(|row| row.try_get(0))
            .collect::<Result<Vec<String>, sqlx::Error>>()?;
        Ok(affected)
    }

    async fn get_invoice_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<Option<Invoice>, LnurlRepositoryError> {
        let maybe_invoice = sqlx::query(
            "SELECT payment_hash, user_pubkey, invoice, preimage, invoice_expiry, created_at, updated_at, domain, amount_received_sat, account_id
             FROM invoices
             WHERE payment_hash = $1",
        )
        .bind(payment_hash)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| {
            Ok::<_, sqlx::Error>(Invoice {
                payment_hash: row.try_get(0)?,
                user_pubkey: row.try_get(1)?,
                invoice: row.try_get(2)?,
                preimage: row.try_get(3)?,
                invoice_expiry: row.try_get(4)?,
                created_at: row.try_get(5)?,
                updated_at: row.try_get(6)?,
                domain: row.try_get(7)?,
                amount_received_sat: row.try_get(8)?,
                account_id: row.try_get(9)?,
            })
        })
        .transpose()?;
        Ok(maybe_invoice)
    }

    async fn get_zap_and_invoice_by_payment_hash(
        &self,
        payment_hash: &str,
    ) -> Result<(Option<Zap>, Option<Invoice>), LnurlRepositoryError> {
        let row = sqlx::query(
            "SELECT z.payment_hash   AS z_payment_hash
             ,      z.zap_request    AS z_zap_request
             ,      z.zap_event      AS z_zap_event
             ,      z.user_pubkey    AS z_user_pubkey
             ,      z.account_id     AS z_account_id
             ,      z.invoice_expiry AS z_invoice_expiry
             ,      z.updated_at     AS z_updated_at
             ,      z.is_user_nostr_key AS z_is_user_nostr_key
             ,      i.payment_hash   AS i_payment_hash
             ,      i.user_pubkey    AS i_user_pubkey
             ,      i.account_id     AS i_account_id
             ,      i.invoice        AS i_invoice
             ,      i.preimage       AS i_preimage
             ,      i.invoice_expiry AS i_invoice_expiry
             ,      i.created_at     AS i_created_at
             ,      i.updated_at     AS i_updated_at
             ,      i.domain         AS i_domain
             ,      i.amount_received_sat AS i_amount_received_sat
             FROM (SELECT $1::text AS payment_hash) ph
             LEFT JOIN zaps z ON z.payment_hash = ph.payment_hash
             LEFT JOIN invoices i ON i.payment_hash = ph.payment_hash",
        )
        .bind(payment_hash)
        .fetch_one(&self.pool)
        .await?;

        let zap = row
            .try_get::<Option<String>, _>("z_payment_hash")?
            .map(|ph| {
                Ok::<_, sqlx::Error>(Zap {
                    payment_hash: ph,
                    zap_request: row.try_get("z_zap_request")?,
                    zap_event: row.try_get("z_zap_event")?,
                    user_pubkey: row.try_get("z_user_pubkey")?,
                    account_id: row.try_get("z_account_id")?,
                    invoice_expiry: row.try_get("z_invoice_expiry")?,
                    updated_at: row.try_get("z_updated_at")?,
                    is_user_nostr_key: row.try_get("z_is_user_nostr_key")?,
                })
            })
            .transpose()?;

        let invoice = row
            .try_get::<Option<String>, _>("i_payment_hash")?
            .map(|ph| {
                Ok::<_, sqlx::Error>(Invoice {
                    payment_hash: ph,
                    user_pubkey: row.try_get("i_user_pubkey")?,
                    account_id: row.try_get("i_account_id")?,
                    invoice: row.try_get("i_invoice")?,
                    preimage: row.try_get("i_preimage")?,
                    invoice_expiry: row.try_get("i_invoice_expiry")?,
                    created_at: row.try_get("i_created_at")?,
                    updated_at: row.try_get("i_updated_at")?,
                    domain: row.try_get("i_domain")?,
                    amount_received_sat: row.try_get("i_amount_received_sat")?,
                })
            })
            .transpose()?;

        Ok((zap, invoice))
    }
    async fn insert_pending_zap_receipt(
        &self,
        pending: &PendingZapReceipt,
    ) -> Result<(), LnurlRepositoryError> {
        sqlx::query(
            "INSERT INTO pending_zap_receipts (payment_hash, created_at, retry_count, next_retry_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(payment_hash) DO NOTHING",
        )
        .bind(&pending.payment_hash)
        .bind(pending.created_at)
        .bind(pending.retry_count)
        .bind(pending.next_retry_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_pending_zap_receipt_batch(
        &self,
        pending: &[PendingZapReceipt],
    ) -> Result<(), LnurlRepositoryError> {
        if pending.is_empty() {
            return Ok(());
        }
        let payment_hashes: Vec<&str> = pending.iter().map(|n| n.payment_hash.as_str()).collect();
        let created_ats: Vec<i64> = pending.iter().map(|n| n.created_at).collect();
        let retry_counts: Vec<i32> = pending.iter().map(|n| n.retry_count).collect();
        let next_retry_ats: Vec<i64> = pending.iter().map(|n| n.next_retry_at).collect();

        sqlx::query(
            "INSERT INTO pending_zap_receipts (payment_hash, created_at, retry_count, next_retry_at)
             SELECT * FROM UNNEST($1::text[], $2::bigint[], $3::int[], $4::bigint[])
             ON CONFLICT(payment_hash) DO NOTHING",
        )
        .bind(&payment_hashes)
        .bind(&created_ats)
        .bind(&retry_counts)
        .bind(&next_retry_ats)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn take_pending_zap_receipts(
        &self,
        limit: u32,
    ) -> Result<Vec<PendingZapReceipt>, LnurlRepositoryError> {
        let now = now_millis();
        let stale_threshold = now.saturating_sub(300_000); // 5 minutes
        let rows = sqlx::query(
            "UPDATE pending_zap_receipts
             SET claimed_at = $2
             WHERE payment_hash IN (
                 SELECT payment_hash FROM pending_zap_receipts
                 WHERE next_retry_at <= $1
                   AND COALESCE(claimed_at, 0) < $3
                 ORDER BY next_retry_at ASC
                 LIMIT $4
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING payment_hash, created_at, retry_count, next_retry_at",
        )
        .bind(now)
        .bind(now)
        .bind(stale_threshold)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        let pending = rows
            .into_iter()
            .map(|row| {
                Ok::<_, sqlx::Error>(PendingZapReceipt {
                    payment_hash: row.try_get(0)?,
                    created_at: row.try_get(1)?,
                    retry_count: row.try_get(2)?,
                    next_retry_at: row.try_get(3)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(pending)
    }

    async fn update_pending_zap_receipt_retry(
        &self,
        payment_hash: &str,
        retry_count: i32,
        next_retry_at: i64,
    ) -> Result<(), LnurlRepositoryError> {
        sqlx::query(
            "UPDATE pending_zap_receipts
             SET retry_count = $2, next_retry_at = $3, claimed_at = NULL
             WHERE payment_hash = $1",
        )
        .bind(payment_hash)
        .bind(retry_count)
        .bind(next_retry_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_pending_zap_receipt(
        &self,
        payment_hash: &str,
    ) -> Result<(), LnurlRepositoryError> {
        sqlx::query("DELETE FROM pending_zap_receipts WHERE payment_hash = $1")
            .bind(payment_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_or_create_setting(
        &self,
        key: &str,
        default_value: &str,
    ) -> Result<String, LnurlRepositoryError> {
        let value: String = sqlx::query_scalar(
            "INSERT INTO settings (key, value) VALUES ($1, $2)
             ON CONFLICT(key) DO UPDATE SET value = settings.value
             RETURNING value",
        )
        .bind(key)
        .bind(default_value)
        .fetch_one(&self.pool)
        .await?;
        Ok(value)
    }

    async fn get_webhook_payloads(
        &self,
        payment_hashes: &[String],
    ) -> Result<Vec<WebhookPayloadData>, LnurlRepositoryError> {
        if payment_hashes.is_empty() {
            return Ok(vec![]);
        }
        let hashes: Vec<&str> = payment_hashes.iter().map(String::as_str).collect();
        let rows = sqlx::query(
            "SELECT i.account_id, i.payment_hash, i.user_pubkey, i.invoice, i.preimage, i.amount_received_sat,
                    u.name, u.domain,
                    sc.sender_comment,
                    i.domain
             FROM invoices i
             LEFT JOIN users u ON u.pubkey = i.user_pubkey AND u.domain = i.domain
             LEFT JOIN sender_comments sc ON sc.payment_hash = i.payment_hash
             WHERE i.payment_hash = ANY($1)
               AND i.domain IS NOT NULL
               AND i.preimage IS NOT NULL",
        )
        .bind(&hashes)
        .fetch_all(&self.pool)
        .await?;
        let results = rows
            .into_iter()
            .map(|row| {
                let name: Option<String> = row.try_get(6)?;
                let user_domain: Option<String> = row.try_get(7)?;
                let lightning_address = match (name, user_domain) {
                    (Some(n), Some(d)) => Some(format!("{n}@{d}")),
                    _ => None,
                };
                Ok::<_, sqlx::Error>(WebhookPayloadData {
                    account_id: row.try_get(0)?,
                    payment_hash: row.try_get(1)?,
                    user_pubkey: row.try_get(2)?,
                    invoice: row.try_get(3)?,
                    preimage: row.try_get(4)?,
                    amount_received_sat: row.try_get(5)?,
                    lightning_address,
                    sender_comment: row.try_get(8)?,
                    domain: row.try_get(9)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }
}

#[async_trait::async_trait]
impl crate::webhooks::WebhookRepository for LnurlRepository {
    async fn insert_webhook_deliveries(
        &self,
        deliveries: &[NewWebhookDelivery],
    ) -> Result<(), WebhookRepositoryError> {
        if deliveries.is_empty() {
            return Ok(());
        }
        let now = now_millis();
        let identifiers: Vec<&str> = deliveries.iter().map(|d| d.identifier.as_str()).collect();
        let domains: Vec<&str> = deliveries.iter().map(|d| d.domain.as_str()).collect();
        let payloads: Vec<&str> = deliveries.iter().map(|d| d.payload.as_str()).collect();
        let created_ats: Vec<i64> = vec![now; deliveries.len()];

        sqlx::query(
            "INSERT INTO webhook_deliveries (identifier, domain, payload, created_at, next_retry_at)
             SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::bigint[], $4::bigint[])
             ON CONFLICT (identifier, domain) DO NOTHING",
        )
        .bind(&identifiers)
        .bind(&domains)
        .bind(&payloads)
        .bind(&created_ats)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn take_pending_webhook_deliveries(
        &self,
    ) -> Result<Vec<WebhookDelivery>, WebhookRepositoryError> {
        let now = now_millis();
        let stale_threshold = now.saturating_sub(300_000); // 5 minutes
        let rows = sqlx::query(
            "UPDATE webhook_deliveries
             SET claimed_at = $2
             WHERE id IN (
                 SELECT d.id
                 FROM (
                     SELECT DISTINCT domain
                     FROM webhook_deliveries
                     WHERE next_retry_at <= $1
                       AND succeeded_at IS NULL
                       AND COALESCE(claimed_at, 0) < $3
                 ) domains
                 CROSS JOIN LATERAL (
                     SELECT id
                     FROM webhook_deliveries
                     WHERE domain = domains.domain
                       AND next_retry_at <= $1
                       AND succeeded_at IS NULL
                       AND COALESCE(claimed_at, 0) < $3
                     ORDER BY next_retry_at ASC
                     FOR UPDATE SKIP LOCKED
                     LIMIT 1
                 ) d
             )
             RETURNING id, identifier, domain, url, payload, created_at, retry_count, next_retry_at",
        )
        .bind(now)
        .bind(now)
        .bind(stale_threshold)
        .fetch_all(&self.pool)
        .await?;
        let deliveries = rows
            .into_iter()
            .map(|row| {
                Ok::<_, sqlx::Error>(WebhookDelivery {
                    id: row.try_get(0)?,
                    identifier: row.try_get(1)?,
                    domain: row.try_get(2)?,
                    url: row.try_get(3)?,
                    payload: row.try_get(4)?,
                    created_at: row.try_get(5)?,
                    retry_count: row.try_get(6)?,
                    next_retry_at: row.try_get(7)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(deliveries)
    }

    async fn update_webhook_delivery_success(
        &self,
        id: i64,
        succeeded_at: i64,
        url: &str,
    ) -> Result<(), WebhookRepositoryError> {
        sqlx::query("UPDATE webhook_deliveries SET succeeded_at = $2, url = $3 WHERE id = $1")
            .bind(id)
            .bind(succeeded_at)
            .bind(url)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn update_webhook_delivery_failure(
        &self,
        id: i64,
        retry_count: i32,
        next_retry_at: i64,
        status_code: Option<i32>,
        body: Option<&str>,
        url: &str,
    ) -> Result<(), WebhookRepositoryError> {
        sqlx::query(
            "UPDATE webhook_deliveries
             SET retry_count = $2, next_retry_at = $3, claimed_at = NULL,
                 last_error_status_code = $4, last_error_body = $5, url = $6
             WHERE id = $1",
        )
        .bind(id)
        .bind(retry_count)
        .bind(next_retry_at)
        .bind(status_code)
        .bind(body)
        .bind(url)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn unclaim_webhook_deliveries(&self, ids: &[i64]) -> Result<(), WebhookRepositoryError> {
        if ids.is_empty() {
            return Ok(());
        }
        sqlx::query("UPDATE webhook_deliveries SET claimed_at = NULL WHERE id = ANY($1)")
            .bind(ids)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_webhook_deliveries_older_than(
        &self,
        before: i64,
    ) -> Result<u64, WebhookRepositoryError> {
        let result = sqlx::query("DELETE FROM webhook_deliveries WHERE created_at < $1")
            .bind(before)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn delete_webhook_delivery(&self, id: i64) -> Result<(), WebhookRepositoryError> {
        sqlx::query("DELETE FROM webhook_deliveries WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn park_webhook_delivery(&self, id: i64) -> Result<(), WebhookRepositoryError> {
        sqlx::query(
            "UPDATE webhook_deliveries SET next_retry_at = $2, claimed_at = NULL WHERE id = $1",
        )
        .bind(id)
        .bind(i64::MAX)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_webhook_configs(&self) -> Result<Vec<WebhookConfig>, WebhookRepositoryError> {
        let rows = sqlx::query("SELECT domain, url, webhook_secret FROM domain_webhooks")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(WebhookConfig {
                    domain: row.try_get(0)?,
                    url: row.try_get(1)?,
                    secret: row.try_get(2)?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(|e| WebhookRepositoryError::General(e.into()))
    }
}

#[cfg(test)]
mod provider_neutral_tests {
    use super::LnurlRepository;
    use crate::repository::{
        AccountIdentifierKind, AccountProvider, IdentifierTransfer, LnurlRepository as _,
        LnurlRepositoryError, NewAccountIdentifier, NewBlinkAccount, NewSparkRegistration,
        WalletKind, generate_account_id, shared_tests,
    };
    use crate::time::now;

    async fn setup_test_db() -> Option<(sqlx::PgPool, LnurlRepository)> {
        let url = std::env::var("LNURL_TEST_POSTGRES_URL").ok()?;
        let pool = sqlx::PgPool::connect(&url).await.ok()?;
        crate::postgresql::run_migrations(&pool).await.ok()?;
        sqlx::query(
            "TRUNCATE account_identifiers, spark_accounts, blink_accounts, accounts CASCADE",
        )
        .execute(&pool)
        .await
        .ok()?;
        sqlx::query("DELETE FROM users").execute(&pool).await.ok()?;
        let db = LnurlRepository::new(pool.clone());
        Some((pool, db))
    }

    #[tokio::test]
    async fn identifier_conflict_is_global() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::identifier_conflict_is_global(&db).await;
    }

    #[tokio::test]
    async fn spark_registration_dual_writes_provider_neutral_rows() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::spark_registration_dual_writes_provider_neutral_rows(&db).await;
    }

    #[tokio::test]
    async fn spark_phone_identifier_is_rejected() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::spark_phone_identifier_is_rejected(&db).await;
    }

    #[tokio::test]
    async fn blink_account_creation_is_atomic() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::blink_account_creation_is_atomic(&db).await;
    }

    #[tokio::test]
    async fn blink_duplicate_account_returns_blink_account_exists() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::blink_duplicate_account_returns_blink_account_exists(&db).await;
    }

    #[tokio::test]
    async fn lookup_by_identifier_account_id_and_spark_pubkey_round_trips() {
        let Some((pool, db)) = setup_test_db().await else {
            return;
        };
        let now = now();
        let account_id = "acct_spark_pg_lookup_task1";

        sqlx::query(
            "INSERT INTO accounts (account_id, provider, created_at, updated_at)
             VALUES ($1, $2, $3, $3)
             ON CONFLICT(account_id) DO UPDATE
             SET provider = excluded.provider
             ,   updated_at = excluded.updated_at",
        )
        .bind(account_id)
        .bind(AccountProvider::Spark.as_str())
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO spark_accounts (account_id, pubkey, created_at, updated_at)
             VALUES ($1, $2, $3, $3)
             ON CONFLICT(account_id) DO UPDATE
             SET pubkey = excluded.pubkey
             ,   updated_at = excluded.updated_at",
        )
        .bind(account_id)
        .bind("spark_pg_lookup_task1_pubkey")
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO account_identifiers (account_id, domain, identifier, identifier_kind, description, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $6)
             ON CONFLICT(account_id, domain, identifier) DO UPDATE
             SET identifier_kind = excluded.identifier_kind
             ,   description = excluded.description
             ,   updated_at = excluded.updated_at",
        )
        .bind(account_id)
        .bind("pg-lookup.example.com")
        .bind("erin")
        .bind("username")
        .bind("lookup")
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        let recipient = db
            .resolve_recipient_by_identifier("pg-lookup.example.com", "erin")
            .await
            .unwrap()
            .expect("identifier lookup should find account");
        let by_id = db
            .get_account_by_id(account_id)
            .await
            .unwrap()
            .expect("account id lookup should find account");
        let by_pubkey = db
            .get_account_by_spark_pubkey("spark_pg_lookup_task1_pubkey")
            .await
            .unwrap()
            .expect("Spark pubkey lookup should find account");
        assert_eq!(recipient.account_id, account_id);
        assert_eq!(recipient.provider, AccountProvider::Spark);
        assert_eq!(
            recipient.spark_pubkey.as_deref(),
            Some("spark_pg_lookup_task1_pubkey")
        );
        assert_eq!(by_id.account_id, account_id);
        assert_eq!(by_pubkey.account_id, account_id);
    }

    #[tokio::test]
    async fn transfer_identifier_requires_source_owner() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::transfer_identifier_requires_source_owner(&db).await;
    }

    #[tokio::test]
    async fn side_effect_records_round_trip_account_id() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::side_effect_records_round_trip_account_id(&db).await;
    }

    #[tokio::test]
    async fn metadata_account_id_round_trips_and_legacy_rows_remain_none() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::metadata_account_id_round_trips_and_legacy_rows_remain_none(&db).await;
    }

    #[tokio::test]
    async fn delete_spark_registration_preserves_account_with_side_effect_ownership() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::delete_spark_registration_preserves_account_with_side_effect_ownership(&db)
            .await;
    }

    #[tokio::test]
    async fn create_blink_account_rejects_existing_spark_account_id() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::create_blink_account_rejects_existing_spark_account_id_with_invalid_provider(
            &db,
        )
        .await;
    }

    #[tokio::test]
    async fn create_blink_account_rejects_existing_inconsistent_blink_account_id() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        shared_tests::create_blink_account_rejects_existing_inconsistent_blink_account_id_with_invalid_ownership(&db)
            .await;
    }

    #[tokio::test]
    async fn rejected_spark_phone_identifier_leaves_no_partial_rows() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        let account_id = generate_account_id(AccountProvider::Spark);

        let result = db
            .upsert_spark_registration(&NewSparkRegistration {
                account_id: Some(account_id.clone()),
                pubkey: "pg_spark_rejected_phone_pubkey".to_string(),
                identifier: NewAccountIdentifier {
                    domain: "pg-reject-phone.example.com".to_string(),
                    identifier: "+573005871212".to_string(),
                    identifier_kind: AccountIdentifierKind::Phone,
                    description: "must fail".to_string(),
                },
            })
            .await;

        assert!(matches!(
            result,
            Err(LnurlRepositoryError::InvalidIdentifierKind)
        ));
        assert!(db.get_account_by_id(&account_id).await.unwrap().is_none());
        assert!(
            db.get_account_by_spark_pubkey("pg_spark_rejected_phone_pubkey")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn duplicate_blink_account_leaves_new_identifier_unclaimed() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        let account = NewBlinkAccount {
            account_id: Some(generate_account_id(AccountProvider::Blink)),
            blink_account_id: "pg_blink_atomic_duplicate".to_string(),
            btc_wallet_id: "pg_blink_atomic_duplicate_btc".to_string(),
            usd_wallet_id: "pg_blink_atomic_duplicate_usd".to_string(),
            default_wallet: WalletKind::Btc,
            identifiers: vec![NewAccountIdentifier {
                domain: "pg-duplicate-atomic.example.com".to_string(),
                identifier: "first".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "first".to_string(),
            }],
        };
        db.create_blink_account(&account).await.unwrap();

        let second_account_id = generate_account_id(AccountProvider::Blink);
        let result = db
            .create_blink_account(&NewBlinkAccount {
                account_id: Some(second_account_id.clone()),
                identifiers: vec![NewAccountIdentifier {
                    domain: "pg-duplicate-atomic.example.com".to_string(),
                    identifier: "second".to_string(),
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
        assert!(
            db.get_account_by_id(&second_account_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.resolve_recipient_by_identifier("pg-duplicate-atomic.example.com", "second")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn transfer_identifier_moves_only_requested_identifier() {
        let Some((_, db)) = setup_test_db().await else {
            return;
        };
        let source_account_id = generate_account_id(AccountProvider::Blink);
        let destination_account_id = generate_account_id(AccountProvider::Spark);

        db.create_blink_account(&NewBlinkAccount {
            account_id: Some(source_account_id.clone()),
            blink_account_id: "pg_blink_transfer_account".to_string(),
            btc_wallet_id: "pg_blink_transfer_btc".to_string(),
            usd_wallet_id: "pg_blink_transfer_usd".to_string(),
            default_wallet: WalletKind::Btc,
            identifiers: vec![
                NewAccountIdentifier {
                    domain: "pg-transfer-success.example.com".to_string(),
                    identifier: "moving".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "moves".to_string(),
                },
                NewAccountIdentifier {
                    domain: "pg-transfer-success.example.com".to_string(),
                    identifier: "stays".to_string(),
                    identifier_kind: AccountIdentifierKind::Username,
                    description: "stays".to_string(),
                },
            ],
        })
        .await
        .unwrap();
        db.upsert_spark_registration(&NewSparkRegistration {
            account_id: Some(destination_account_id.clone()),
            pubkey: "pg_spark_transfer_destination".to_string(),
            identifier: NewAccountIdentifier {
                domain: "pg-transfer-success.example.com".to_string(),
                identifier: "sparkdest".to_string(),
                identifier_kind: AccountIdentifierKind::Username,
                description: "destination".to_string(),
            },
        })
        .await
        .unwrap();

        db.transfer_identifier(&IdentifierTransfer {
            domain: "pg-transfer-success.example.com".to_string(),
            identifier: "moving".to_string(),
            source_account_id: source_account_id.clone(),
            destination_account_id: destination_account_id.clone(),
            description: "moved".to_string(),
        })
        .await
        .unwrap();

        let moved = db
            .resolve_recipient_by_identifier("pg-transfer-success.example.com", "moving")
            .await
            .unwrap()
            .unwrap();
        let stayed = db
            .resolve_recipient_by_identifier("pg-transfer-success.example.com", "stays")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(moved.account_id, destination_account_id);
        assert_eq!(moved.description, "moved");
        assert_eq!(stayed.account_id, source_account_id);
    }
}
