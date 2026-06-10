#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletModifier {
    Btc,
    Usd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierKind {
    Username,
    Phone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedIdentifier {
    pub canonical: String,
    pub kind: IdentifierKind,
    pub wallet: Option<WalletModifier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierError {
    EmptyIdentifier,
    InvalidUsername,
    InvalidPhoneNumber,
    InvalidModifier,
}

pub fn checked_to_username(_value: &str) -> Result<String, IdentifierError> {
    Err(IdentifierError::InvalidUsername)
}

pub fn checked_to_phone_number(_value: &str) -> Result<String, IdentifierError> {
    Err(IdentifierError::InvalidPhoneNumber)
}

pub fn parse_public_identifier(_value: &str) -> Result<ParsedIdentifier, IdentifierError> {
    Err(IdentifierError::EmptyIdentifier)
}

pub fn canonical_spark_username(value: &str) -> Result<String, IdentifierError> {
    checked_to_username(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d09_username_semantics_match_blink_core_checked_to_username() {
        assert_eq!(checked_to_username("Alice_123"), Ok("alice_123".to_string()));
        assert_eq!(checked_to_username("  Alice_123  "), Ok("alice_123".to_string()));

        for invalid in ["", "   ", "12345", "bc1alice", "lnbc1pay", "_alice", "ab"] {
            assert_eq!(checked_to_username(invalid), Err(IdentifierError::InvalidUsername));
        }

        let too_long = format!("a{}", "1".repeat(50));
        assert_eq!(checked_to_username(&too_long), Err(IdentifierError::InvalidUsername));
        assert_eq!(canonical_spark_username("Alice_123"), Ok("alice_123".to_string()));
    }

    #[test]
    fn d01_d02_d03_d04_phone_equivalence_uses_e164_canonical_form() {
        for input in ["573005871212", "+573005871212", "00573005871212"] {
            assert_eq!(checked_to_phone_number(input), Ok("+573005871212".to_string()));
        }
    }

    #[test]
    fn d04_phone_invalid_vectors_reject_local_impossible_and_non_geographic() {
        for invalid in ["3005871212", "+573", "+999123456789", "+80012345678", "not-a-phone"] {
            assert_eq!(checked_to_phone_number(invalid), Err(IdentifierError::InvalidPhoneNumber));
        }
    }

    #[test]
    fn d05_d06_modifier_parsing_is_final_suffix_only_and_case_insensitive() {
        for input in ["alice+BTC", "alice+btc", "alice+BtC"] {
            assert_eq!(
                parse_public_identifier(input),
                Ok(ParsedIdentifier {
                    canonical: "alice".to_string(),
                    kind: IdentifierKind::Username,
                    wallet: Some(WalletModifier::Btc),
                })
            );
        }

        assert_eq!(
            parse_public_identifier("alice+usd"),
            Ok(ParsedIdentifier {
                canonical: "alice".to_string(),
                kind: IdentifierKind::Username,
                wallet: Some(WalletModifier::Usd),
            })
        );
    }

    #[test]
    fn d07_d08_modifier_strictness_rejects_unknown_and_chained_suffixes() {
        for invalid in ["alice+eur", "alice+btc+usd", "alice+btc+btc"] {
            assert_eq!(parse_public_identifier(invalid), Err(IdentifierError::InvalidModifier));
        }
    }

    #[test]
    fn iden05_numeric_phone_routing_does_not_fall_back_to_username() {
        assert_eq!(
            parse_public_identifier("573005871212"),
            Ok(ParsedIdentifier {
                canonical: "+573005871212".to_string(),
                kind: IdentifierKind::Phone,
                wallet: None,
            })
        );

        assert_eq!(parse_public_identifier("12345"), Err(IdentifierError::InvalidPhoneNumber));
    }
}
