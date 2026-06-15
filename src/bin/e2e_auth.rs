async fn build_payload_json(
    username: &str,
    timestamp: u64,
) -> Result<serde_json::Value, anyhow::Error> {
    let payload = spark_client::Client::build_auth_payload(username, timestamp).await?;

    Ok(serde_json::json!({
        "pubkey": payload.pubkey,
        "timestamp": payload.timestamp,
        "register_signature": payload.register_signature,
        "recover_signature": payload.recover_signature,
        "unregister_signature": payload.unregister_signature,
        "to_pubkey": payload.to_pubkey,
        "to_register_signature": payload.to_register_signature,
        "to_recover_signature": payload.to_recover_signature,
        "transfer_from_signature": payload.transfer_from_signature,
        "transfer_to_signature": payload.transfer_to_signature,
    }))
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let username = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "alice".to_string());
    let timestamp = std::env::args()
        .nth(2)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is before unix epoch")
                .as_secs()
        });

    println!("{}", build_payload_json(&username, timestamp).await?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn auth_payload_includes_deterministic_transfer_signatures() {
        let payload = build_payload_json("transferuser", 1).await.unwrap();

        assert!(
            payload["pubkey"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            payload["to_pubkey"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            payload["to_recover_signature"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert_ne!(payload["pubkey"], payload["to_pubkey"]);
        assert!(
            payload["transfer_from_signature"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            payload["transfer_to_signature"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }
}
