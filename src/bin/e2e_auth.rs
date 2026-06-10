use spark::signer::{DefaultSigner, Signer};
use spark_wallet::Network;

async fn sign(signer: &DefaultSigner, message: String) -> Result<String, anyhow::Error> {
    let signature = signer
        .sign_message_ecdsa_with_identity_key(message.as_bytes())
        .await?;
    Ok(hex::encode(signature.serialize_der()))
}

async fn build_payload_json(
    username: &str,
    timestamp: u64,
) -> Result<serde_json::Value, anyhow::Error> {
    let signer = DefaultSigner::new(&[42u8; 32], Network::Regtest)?;
    let pubkey = signer.get_identity_public_key().await?.to_string();

    let to_signer = DefaultSigner::new(&[43u8; 32], Network::Regtest)?;
    let to_pubkey = to_signer.get_identity_public_key().await?.to_string();

    let register_signature = sign(&signer, format!("{username}-{timestamp}")).await?;
    let recover_signature = sign(&signer, format!("{pubkey}-{timestamp}")).await?;
    let to_register_signature = sign(&to_signer, format!("{username}-{timestamp}")).await?;
    let transfer_message = format!("transfer:{username}-{to_pubkey}");
    let transfer_from_signature = sign(&signer, transfer_message.clone()).await?;
    let transfer_to_signature = sign(&to_signer, transfer_message).await?;

    Ok(serde_json::json!({
        "pubkey": pubkey,
        "timestamp": timestamp,
        "register_signature": register_signature,
        "recover_signature": recover_signature,
        "unregister_signature": register_signature,
        "to_pubkey": to_pubkey,
        "to_register_signature": to_register_signature,
        "transfer_from_signature": transfer_from_signature,
        "transfer_to_signature": transfer_to_signature,
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
