/// Domain and description the v2 signatures commit to unless given.
const DEFAULT_DOMAIN: &str = "localhost:8080";
const DEFAULT_DESCRIPTION: &str = "Test LNURL user";

async fn build_payload_json(
    username: &str,
    timestamp: u64,
    domain: &str,
    description: &str,
) -> Result<serde_json::Value, anyhow::Error> {
    let payload = spark_client::Client::build_auth_payload(username, timestamp).await?;
    let v2 = spark_client::Client::build_v2_auth_payload(username, timestamp, domain, description)
        .await?;

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
        "v2": {
            "domain": v2.domain,
            "description": v2.description,
            "available_signature": v2.available_signature,
            "register_signature": v2.register_signature,
            "unregister_signature": v2.unregister_signature,
            "recover_signature": v2.recover_signature,
            "metadata_signature": v2.metadata_signature,
            "to_recover_signature": v2.to_recover_signature,
            "transfer_from_signature": v2.transfer_from_signature,
            "transfer_to_signature": v2.transfer_to_signature,
        },
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

    let domain = std::env::args()
        .nth(3)
        .unwrap_or_else(|| DEFAULT_DOMAIN.to_string());
    let description = std::env::args()
        .nth(4)
        .unwrap_or_else(|| DEFAULT_DESCRIPTION.to_string());

    println!(
        "{}",
        build_payload_json(&username, timestamp, &domain, &description).await?
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn auth_payload_includes_deterministic_transfer_signatures() {
        let payload = build_payload_json("transferuser", 1, DEFAULT_DOMAIN, DEFAULT_DESCRIPTION)
            .await
            .unwrap();

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
        for key in [
            "available_signature",
            "register_signature",
            "unregister_signature",
            "recover_signature",
            "metadata_signature",
            "to_recover_signature",
            "transfer_from_signature",
            "transfer_to_signature",
        ] {
            assert!(
                payload["v2"][key]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()),
                "missing v2 {key}"
            );
        }
    }
}
