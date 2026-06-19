use sqlx::PgPool;

use crate::repository::LnurlRepositoryError;

mod repository;

pub async fn run_migrations(pool: &PgPool) -> Result<(), LnurlRepositoryError> {
    let migrator = sqlx::migrate!("migrations/postgres");
    Ok(migrator.run(pool).await?)
}

pub use repository::LnurlRepository;

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn migrations_do_not_create_legacy_users_table() {
        let Some(url) = std::env::var("LNURL_TEST_POSTGRES_URL").ok() else {
            return;
        };
        let pool = sqlx::PgPool::connect(&url).await.unwrap();

        super::run_migrations(&pool).await.unwrap();

        let exists: Option<String> = sqlx::query_scalar("SELECT to_regclass('public.users')")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert!(exists.is_none(), "legacy users table should be removed");
    }
}
