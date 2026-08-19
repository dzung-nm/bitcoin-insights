use k256::SecretKey;
use k256::elliptic_curve::sec1::ToSec1Point;
use rand::{rng, RngExt};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

/// Compute the HASH160 (RIPEMD-160 of SHA-256) of the input data.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);

    let mut hasher = Ripemd160::new();
    hasher.update(&sha256_hash);

    let mut result = [0u8; 20];
    result.copy_from_slice(&hasher.finalize());
    result
}

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

/// Create a cryptographic random salt with a specified length in bytes.
pub fn random_salt(length: usize) -> Vec<u8> {
    let mut crypto_rng = rng();

    let mut cryptographic_salt = vec![0u8; length];
    crypto_rng.fill(&mut cryptographic_salt);

    cryptographic_salt
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::*;
    
    #[test]
    fn test_random_salt() {
        let salt_length = 32; // 32 bytes
        let salt = random_salt(salt_length);
        assert_eq!(salt.len(), salt_length);
    }

    #[test]
    fn test_hash160() {
        let data = b"Hello world!";
        let hash = hash160(data);
        let hash_hex = bytes_to_hex(&hash, false);
        assert_eq!(hash_hex, "621281c15fb62d5c6013ea29007491e8b174e1b9");
    }

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
}
