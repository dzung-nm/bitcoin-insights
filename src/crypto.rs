use rand::{RngExt, rng};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Compute the HASH160 (RIPEMD-160 of SHA-256) of the input data.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);

    let mut hasher = Ripemd160::new();
    hasher.update(&sha256_hash);

    let mut result = [0u8; 20];
    result.copy_from_slice(&hasher.finalize());
    result
}

/// Create a cryptographic random salt with a specified length in bytes.
pub fn random_salt(length: usize) -> Vec<u8> {
    let mut crypto_rng = rng();

    let mut cryptographic_salt = vec![0u8; length];
    crypto_rng.fill(&mut cryptographic_salt);

    cryptographic_salt
}

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
}
