use spark::signer::{DefaultSigner, Signer};
use spark_wallet::Network;

async fn sign(signer: &DefaultSigner, message: String) -> Result<String, anyhow::Error> {
    let signature = signer
        .sign_message_ecdsa_with_identity_key(message.as_bytes())
        .await?;
    Ok(hex::encode(signature.serialize_der()))
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

    let signer = DefaultSigner::new(&[42u8; 32], Network::Regtest)?;
    let pubkey = signer.get_identity_public_key().await?.to_string();

    let register_signature = sign(&signer, format!("{username}-{timestamp}")).await?;
    let recover_signature = sign(&signer, format!("{pubkey}-{timestamp}")).await?;

    println!(
        "{}",
        serde_json::json!({
            "pubkey": pubkey,
            "timestamp": timestamp,
            "register_signature": register_signature,
            "recover_signature": recover_signature,
            "unregister_signature": register_signature,
        })
    );

    Ok(())
}
