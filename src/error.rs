use sqlx::migrate::MigrateError;

use crate::repository::LnurlRepositoryError;

impl From<sqlx::Error> for LnurlRepositoryError {
    fn from(err: sqlx::Error) -> Self {
        if let sqlx::Error::Database(database_error) = &err
            && database_error.is_unique_violation()
        {
            match database_error.constraint() {
                Some("account_identifiers_domain_identifier_key") => {
                    return LnurlRepositoryError::IdentifierConflict;
                }
                Some("blink_accounts_blink_account_id_key") => {
                    return LnurlRepositoryError::BlinkAccountExists;
                }
                _ => {}
            }

            // SQLite may not expose named constraint/index metadata through
            // SQLx for every unique violation. Provider-neutral repository
            // writes must still use explicit transactional prechecks for exact
            // IdentifierConflict and BlinkAccountExists errors; this fallback
            // preserves legacy Spark NameTaken compatibility for old callers.
            return LnurlRepositoryError::NameTaken;
        }

        LnurlRepositoryError::General(err.into())
    }
}
impl From<MigrateError> for LnurlRepositoryError {
    fn from(err: MigrateError) -> Self {
        LnurlRepositoryError::General(err.into())
    }
}
