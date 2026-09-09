use k256::SecretKey;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::ecdsa::{Signature as EcdsaSignature, VerifyingKey};
use k256::ecdsa::signature::Verifier;

/// Generate compressed public key (33 bytes) from a 32-byte private key.
pub fn get_compressed_pubkey(priv_key_bytes: &[u8; 32]) -> [u8; 33] {
    let secret_key =
        SecretKey::from_bytes(priv_key_bytes.into()).expect("Invalid private key bytes");
    let public_key = secret_key.public_key();

    // Serialize public key to compressed format (33 bytes)
    let encoded_point = public_key.to_sec1_point(true);

    encoded_point
        .as_bytes()
        .try_into()
        .expect("Compressed public key must be 33 bytes")
}

/// Verify an ECDSA signature given the public key, signature, and transaction hash.
pub fn verify_signature(pubkey_bytes: &[u8], sig_bytes: &[u8], tx_hash: &[u8; 32]) -> bool {
    if sig_bytes.len() < 2 {
        return false;
    }

    // Remove the last byte (SIGHASH type) from the signature to get the original DER signature
    let der_sig_bytes = &sig_bytes[..sig_bytes.len() - 1];

    // Parse the public key bytes into a VerifyingKey. If parsing fails, return false.
    let verifying_key = match VerifyingKey::from_sec1_bytes(pubkey_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Parse the DER-encoded signature. If parsing fails, return false.
    let signature = match EcdsaSignature::from_der(der_sig_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Verify the signature with the transaction hash
    verifying_key.verify(tx_hash, &signature).is_ok()
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes_to_hex;
    use k256::ecdsa::signature::Signer;
    
    #[test]
    fn test_get_compressed_pubkey() {
        // Example private key (32 bytes)
        let priv_key_bytes: [u8; 32] = [
            0x1e, 0x99, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
            0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07,
            0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
            0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07,
        ];

        let compressed_pubkey = get_compressed_pubkey(&priv_key_bytes);

        assert_eq!(compressed_pubkey.len(), 33);
        assert!(compressed_pubkey[0] == 2 || compressed_pubkey[0] == 3); // Check prefix

        let pubkey_hex = bytes_to_hex(&compressed_pubkey, true);

        let expected = "0x02e0d7fb2551f38d96349c627b71a477774c9befa6dca866ac5425cbfce6e51961";
        assert_eq!(pubkey_hex, expected);
    }

    #[test]
    fn test_verify_signature() {
        // Example private key (32 bytes)
        let priv_key_bytes: [u8; 32] = [
            0x1e, 0x99, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
            0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07,
            0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
            0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07,
        ];

        let compressed_pubkey = get_compressed_pubkey(&priv_key_bytes);

        // Simulate a transaction hash for testing purposes
        let tx_hash: [u8; 32] = [0x42; 32];

        // Create a signature DER and append SIGHASH_ALL (0x01)
        let secret_key = SecretKey::from_bytes((&priv_key_bytes).into()).unwrap();
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let signature: k256::ecdsa::Signature = signing_key.sign(&tx_hash);
        let mut sig_bytes = signature.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        // Verify the signature using the public key and transaction hash
        assert!(verify_signature(&compressed_pubkey, &sig_bytes, &tx_hash));

        // Wrong tx hash should fail
        let wrong_tx_hash: [u8; 32] = [0x43; 32];
        assert!(!verify_signature(&compressed_pubkey, &sig_bytes, &wrong_tx_hash));

        // Wrong sighash byte still verifies because current implementation strips last byte
        let mut wrong_sighash_sig = sig_bytes.clone();
        *wrong_sighash_sig.last_mut().unwrap() = 0x02;
        assert!(verify_signature(&compressed_pubkey, &wrong_sighash_sig, &tx_hash));

        // Missing sighash marker (no trailing byte) should fail due to broken DER after strip
        let der_only_sig = signature.to_der().as_bytes().to_vec();
        assert!(!verify_signature(&compressed_pubkey, &der_only_sig, &tx_hash));

        // Corrupted signature should fail
        let mut bad_sig = sig_bytes.clone();
        bad_sig[10] ^= 0x01;
        assert!(!verify_signature(&compressed_pubkey, &bad_sig, &tx_hash));

        // Invalid public key should fail
        let bad_pubkey = vec![0x04, 0x01, 0x02];
        assert!(!verify_signature(&bad_pubkey, &sig_bytes, &tx_hash));
    }
}
