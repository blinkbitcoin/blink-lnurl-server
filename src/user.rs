/// Legacy-only username validation: alphanumeric plus a limited set of special characters,
/// with dots allowed (but not leading, trailing, or consecutive). This is the
/// unquoted local-part from RFC 5322 without the quoted-string alternative that
/// would allow control characters.
///
/// New Spark create/update validation uses the shared Blink Core-compatible
/// identifier parser instead of this regex.
#[allow(dead_code)]
pub const USERNAME_VALIDATION_REGEX: &str =
    "^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*$";

pub struct User {
    pub domain: String,
    pub pubkey: String,
    pub name: String,
    pub description: String,
}

#[cfg(test)]
mod tests {
    use crate::identifier::{IdentifierError, canonical_spark_username, checked_to_phone_number};

    #[test]
    fn username_validation_rejects_numeric_only_collisions_test_01() {
        for valid in ["alice", "Alice_123", "blink_user_9"] {
            assert!(
                canonical_spark_username(valid).is_ok(),
                "valid Blink-compatible username should pass: {valid}"
            );
        }

        for invalid in ["12345", "3005871212", "573005871212", "000"] {
            assert_eq!(
                canonical_spark_username(invalid),
                Err(IdentifierError::InvalidUsername),
                "numeric-only identifiers must not collide with username namespace: {invalid}"
            );
        }
    }

    #[test]
    fn phone_normalization_equivalent_inputs_match_test_01() {
        let canonical = checked_to_phone_number("+573005871212").expect("fixture phone is valid");

        for input in ["573005871212", "+573005871212", "00573005871212"] {
            assert_eq!(
                checked_to_phone_number(input),
                Ok(canonical.clone()),
                "equivalent phone input should normalize consistently: {input}"
            );
        }

        assert_eq!(canonical, "+573005871212");
        assert_eq!(
            checked_to_phone_number("3005871212"),
            Err(IdentifierError::InvalidPhoneNumber),
            "local-looking numeric input must not be persisted as a wallet alias"
        );
    }
}
