use anyhow::Result;
use shared_crypto::intent::Intent;
use sui_sdk::types::crypto::{SuiKeyPair, Signature, SignatureScheme};

/// Load a keypair from a base64-encoded private key string.
/// Get this from: `sui keytool export --key-identity <address>`
pub fn load_keypair(private_key_b64: &str) -> Result<SuiKeyPair> {
    let keypair = SuiKeyPair::decode_base64(private_key_b64)
        .map_err(|e| anyhow::anyhow!("Failed to decode keypair: {e}"))?;
    Ok(keypair)
}

/// Extension trait to sign a TransactionData with a SuiKeyPair.
pub trait SignTransaction {
    fn sign_transaction(
        &self,
        tx_data: &sui_sdk::types::transaction::TransactionData,
    ) -> Signature;
}

impl SignTransaction for SuiKeyPair {
    fn sign_transaction(
        &self,
        tx_data: &sui_sdk::types::transaction::TransactionData,
    ) -> Signature {
        Signature::new_secure(
            &sui_sdk::types::transaction::TransactionData::intent_message(
                Intent::sui_transaction(),
                tx_data,
            ),
            self,
        )
    }
}