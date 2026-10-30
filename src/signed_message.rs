//! Canonical messages a Spark identity key signs to authorize a request on the
//! `/lnurlpay/{pubkey}` management routes.
//!
//! The `breez-lnurl:v2` builders come from Breez's `lnurl-models` crate, which
//! the SDK signs with, so the bytes verified here are the bytes clients sign.
//! The golden vectors below pin them in this repository too: a dependency bump
//! that changes them breaks every deployed client, so a failure here is a wire
//! break rather than a test to update.

#[cfg(test)]
mod tests {
    use lnurl_models::signed_message::{
        VALIDITY_SECS, available, description_hash, metadata, recover, register, transfer_from,
        transfer_to, unregister,
    };

    const DOMAIN: &str = "lnurl.example.com";
    const ALICE: &str = "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc";
    const BOB: &str = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// Copied from `lnurl-models/src/signed_message.rs` at tag `0.23.1`.
    #[test]
    fn breez_v2_golden_vectors() {
        assert_eq!(
            register(DOMAIN, "alice", "Pay to alice", 1_700_000_000),
            concat!(
                "breez-lnurl:v2\nregister\nlnurl.example.com\nalice\n",
                "0261d8b11c7eba9f71ccf5180df58416d3b2d19ba917caf57ba4bacead3ce2c2",
                "\n1700000000"
            )
        );
        assert_eq!(
            unregister(DOMAIN, "alice", 1_700_000_000),
            "breez-lnurl:v2\nunregister\nlnurl.example.com\nalice\n1700000000"
        );
        assert_eq!(
            recover(DOMAIN, ALICE, 1_700_000_000),
            format!("breez-lnurl:v2\nrecover\nlnurl.example.com\n{ALICE}\n1700000000")
        );
        assert_eq!(
            metadata(DOMAIN, ALICE, 1_700_000_000),
            format!("breez-lnurl:v2\nmetadata\nlnurl.example.com\n{ALICE}\n1700000000")
        );
        assert_eq!(
            available(DOMAIN, ALICE, "alice", 1_700_000_000),
            format!("breez-lnurl:v2\navailable\nlnurl.example.com\n{ALICE}\nalice\n1700000000")
        );
        assert_eq!(
            transfer_from(DOMAIN, "alice", ALICE, BOB, 1_700_000_000),
            format!(
                "breez-lnurl:v2\ntransfer-from\nlnurl.example.com\nalice\n{ALICE}\n{BOB}\n1700000000"
            )
        );
        assert_eq!(
            transfer_to(DOMAIN, "alice", ALICE, BOB, "Pay to alice", 1_700_000_000),
            format!(
                "breez-lnurl:v2\ntransfer-to\nlnurl.example.com\nalice\n{ALICE}\n{BOB}\n\
                 0261d8b11c7eba9f71ccf5180df58416d3b2d19ba917caf57ba4bacead3ce2c2\n1700000000"
            )
        );
    }

    /// The description is hashed byte-exact, so whitespace is significant.
    #[test]
    fn description_hash_does_not_normalize() {
        assert_ne!(
            description_hash(" Pay to alice "),
            description_hash("Pay to alice")
        );
    }

    /// Breez sizes its accept window here; a server window that drifts from it
    /// refuses requests clients consider fresh.
    #[test]
    fn validity_window_matches_breez() {
        assert_eq!(VALIDITY_SECS, 600);
    }
}
