use std::str::FromStr;

use nostr::{EventBuilder, JsonUtil, Kind, Tag, key::Keys};

const DEFAULT_RELAY: &str = "wss://relay.example.com";
const E2E_ZAP_REQUEST_SECRET_HEX: &str =
    "0202020202020202020202020202020202020202020202020202020202020202";

fn build_zap_request_json(
    recipient_nostr_pubkey: &str,
    amount_msats: u64,
) -> Result<String, anyhow::Error> {
    let keys = Keys::from_str(E2E_ZAP_REQUEST_SECRET_HEX)?;
    let tags = vec![
        Tag::parse(["p", recipient_nostr_pubkey])?,
        Tag::parse(["amount", amount_msats.to_string().as_str()])?,
        Tag::parse(["relays", DEFAULT_RELAY])?,
    ];

    let event = EventBuilder::new(Kind::ZapRequest, "")
        .tags(tags)
        .sign_with_keys(&keys)?;
    Ok(event.as_json())
}

fn parse_args() -> Result<(String, u64), anyhow::Error> {
    let mut args = std::env::args().skip(1);
    let recipient_nostr_pubkey = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("recipient nostr pubkey argument is required"))?;
    let amount_msats = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("amount msats argument is required"))?
        .parse()?;
    Ok((recipient_nostr_pubkey, amount_msats))
}

fn main() -> Result<(), anyhow::Error> {
    let (recipient_nostr_pubkey, amount_msats) = parse_args()?;
    println!(
        "{}",
        build_zap_request_json(&recipient_nostr_pubkey, amount_msats)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zap_request_contains_nip57_tags_and_verifies() {
        let recipient =
            Keys::from_str("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap()
                .public_key()
                .xonly()
                .unwrap()
                .to_string();

        let json = build_zap_request_json(&recipient, 1000).unwrap();
        let event = nostr::Event::from_json(&json).unwrap();

        assert_eq!(event.kind, Kind::ZapRequest);
        assert!(event.verify().is_ok());
        let tags: Vec<Vec<String>> = event.tags.iter().map(|tag| tag.clone().to_vec()).collect();
        assert!(tags.iter().any(|tag| tag == &["p", recipient.as_str()]));
        assert!(tags.iter().any(|tag| tag == &["amount", "1000"]));
        assert!(tags.iter().any(|tag| tag == &["relays", DEFAULT_RELAY]));
    }
}
