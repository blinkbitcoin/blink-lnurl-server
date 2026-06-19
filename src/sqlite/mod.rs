use sqlx::SqlitePool;

use crate::repository::LnurlRepositoryError;

mod repository;

pub async fn run_migrations(pool: &SqlitePool) -> Result<(), LnurlRepositoryError> {
    let migrator = sqlx::migrate!("migrations/sqlite");
    Ok(migrator.run(pool).await?)
}

pub use repository::LnurlRepository;

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn migrations_do_not_create_legacy_users_table() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(":memory:")
            .await
            .unwrap();

        super::run_migrations(&pool).await.unwrap();

        let exists: Option<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        assert!(exists.is_none(), "legacy users table should be removed");
    }
}
