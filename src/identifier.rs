use phonenumber::Mode;

const BLINK_USERNAME_REGEX: &str = r"(?i)^(?![13_]|bc1|lnbc1)(?=.*[a-z])[0-9a-z_]{3,50}$";

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

pub fn checked_to_username(value: &str) -> Result<String, IdentifierError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(IdentifierError::InvalidUsername);
    }

    if !matches_blink_username_regex(trimmed) {
        return Err(IdentifierError::InvalidUsername);
    }

    Ok(trimmed.to_lowercase())
}

pub fn checked_to_phone_number(value: &str) -> Result<String, IdentifierError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(IdentifierError::InvalidPhoneNumber);
    }

    let normalized = if let Some(rest) = trimmed.strip_prefix('+') {
        format!("+{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("00") {
        format!("+{rest}")
    } else {
        format!("+{trimmed}")
    };

    let phone =
        phonenumber::parse(None, &normalized).map_err(|_| IdentifierError::InvalidPhoneNumber)?;

    // Blink Core checks both `country` and `isPossible()` before `isValid()`.
    // `phonenumber` 0.3.9 exposes country metadata and validity on PhoneNumber,
    // but no public per-number `is_possible` method; parse + country metadata +
    // `is_valid()` is the crate-equivalent gate, locked by compatibility vectors.
    if phone.country().id().is_none() || !phone.is_valid() {
        return Err(IdentifierError::InvalidPhoneNumber);
    }

    Ok(phone.format().mode(Mode::E164).to_string())
}

pub fn parse_public_identifier(value: &str) -> Result<ParsedIdentifier, IdentifierError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(IdentifierError::EmptyIdentifier);
    }

    let (base, wallet) = split_final_wallet_modifier(trimmed)?;
    let (canonical, kind) = if is_phone_like(base) {
        (checked_to_phone_number(base)?, IdentifierKind::Phone)
    } else {
        (checked_to_username(base)?, IdentifierKind::Username)
    };

    Ok(ParsedIdentifier {
        canonical,
        kind,
        wallet,
    })
}

pub fn canonical_spark_username(value: &str) -> Result<String, IdentifierError> {
    checked_to_username(value)
}

fn split_final_wallet_modifier(
    value: &str,
) -> Result<(&str, Option<WalletModifier>), IdentifierError> {
    let Some(plus_index) = value
        .char_indices()
        .skip(1)
        .find_map(|(index, ch)| if ch == '+' { Some(index) } else { None })
    else {
        return Ok((value, None));
    };

    let suffix_start = plus_index
        .checked_add(1)
        .ok_or(IdentifierError::InvalidModifier)?;
    let suffix = &value[suffix_start..];
    let wallet = if suffix.eq_ignore_ascii_case("btc") {
        WalletModifier::Btc
    } else if suffix.eq_ignore_ascii_case("usd") {
        WalletModifier::Usd
    } else {
        return Err(IdentifierError::InvalidModifier);
    };

    let base = &value[..plus_index];
    if base.char_indices().skip(1).any(|(_, ch)| ch == '+') {
        return Err(IdentifierError::InvalidModifier);
    }

    Ok((base, Some(wallet)))
}

fn is_phone_like(value: &str) -> bool {
    value.starts_with('+') || value.starts_with("00") || value.chars().all(|ch| ch.is_ascii_digit())
}

fn matches_blink_username_regex(value: &str) -> bool {
    let _ = BLINK_USERNAME_REGEX;
    let lower = value.to_lowercase();
    let len = lower.chars().count();

    // Rust's regex crate intentionally does not support Blink Core's look-around
    // pattern, so this implements BLINK_USERNAME_REGEX equivalently.
    if !(3..=50).contains(&len)
        || lower.starts_with('1')
        || lower.starts_with('3')
        || lower.starts_with('_')
        || lower.starts_with("bc1")
        || lower.starts_with("lnbc1")
    {
        return false;
    }

    let mut has_letter = false;
    for ch in lower.chars() {
        if ch.is_ascii_lowercase() {
            has_letter = true;
        } else if !ch.is_ascii_digit() && ch != '_' {
            return false;
        }
    }

    has_letter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d09_username_semantics_match_blink_core_checked_to_username() {
        assert_eq!(
            checked_to_username("Alice_123"),
            Ok("alice_123".to_string())
        );
        assert_eq!(
            checked_to_username("  Alice_123  "),
            Ok("alice_123".to_string())
        );

        for invalid in ["", "   ", "12345", "bc1alice", "lnbc1pay", "_alice", "ab"] {
            assert_eq!(
                checked_to_username(invalid),
                Err(IdentifierError::InvalidUsername)
            );
        }

        let too_long = format!("a{}", "1".repeat(50));
        assert_eq!(
            checked_to_username(&too_long),
            Err(IdentifierError::InvalidUsername)
        );
        assert_eq!(
            canonical_spark_username("Alice_123"),
            Ok("alice_123".to_string())
        );
    }

    #[test]
    fn d01_d02_d03_d04_phone_equivalence_uses_e164_canonical_form() {
        for input in ["573005871212", "+573005871212", "00573005871212"] {
            assert_eq!(
                checked_to_phone_number(input),
                Ok("+573005871212".to_string())
            );
        }
    }

    #[test]
    fn d04_phone_invalid_vectors_reject_local_impossible_and_non_geographic() {
        for invalid in [
            "3005871212",
            "+573",
            "+999123456789",
            "+80012345678",
            "not-a-phone",
        ] {
            assert_eq!(
                checked_to_phone_number(invalid),
                Err(IdentifierError::InvalidPhoneNumber)
            );
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
            assert_eq!(
                parse_public_identifier(invalid),
                Err(IdentifierError::InvalidModifier)
            );
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

        assert_eq!(
            parse_public_identifier("12345"),
            Err(IdentifierError::InvalidPhoneNumber)
        );
    }
}
