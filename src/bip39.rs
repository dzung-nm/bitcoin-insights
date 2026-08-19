// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Get the bit at position i from the byte array data
fn get_bit(data: &[u8], i: usize) -> u8 {
    (data[i / 8] >> (7 - (i % 8))) & 1
}

/// Read mnemonic words from the english.txt file
fn read_mnemonic_words() -> Vec<String> {
    let file = File::open("src/mnemonic/english.txt").expect("Failed to open english.txt");
    let reader = BufReader::new(file);
    reader
        .lines()
        .map(|line| line.expect("Failed to read line"))
        .filter(|line| !line.is_empty())
        .collect()
}

/// Generate a mnemonic phrase from a given salt
pub fn generate_mnemonic_from_salt(salt: &[u8]) -> Vec<String> {
    // Valid salt lengths are 16, 20, 24, 28, or 32 bytes (128, 160, 192, 224, or 256 bits)
    if ![16, 20, 24, 28, 32].contains(&salt.len()) {
        panic!("Invalid salt length. Must be 16, 20, 24, 28, or 32 bytes.");
    }

    let mnemonic_words = read_mnemonic_words();

    let entropy_length = salt.len() * 8; // Entropy length in bits [128, 160, 192, 224, 256]
    let checksum_length = entropy_length / 32; // Checksum length in bits [4, 5, 6, 7, 8]
    let total_bits = entropy_length + checksum_length; // [132, 165, 198, 231, 264]

    let hash_bytes = Sha256::digest(salt);

    let mut data = vec![0u8; salt.len() + 1]; // Extra byte for checksum
    data[..salt.len()].copy_from_slice(salt);
    data[salt.len()] = hash_bytes[0];

    // Now we can generate the mnemonic words
    let mut mnemonic = Vec::new();
    let word_count = total_bits / 11;

    for i in 0..word_count {
        let mut index: u16 = 0;
        for j in 0..11 {
            let bit_position = i * 11 + j;
            let bit = get_bit(&data, bit_position);
            index = (index << 1) | (bit as u16);
        }
        mnemonic.push(mnemonic_words[index as usize].clone());
    }

    mnemonic
}

/// Convert a mnemonic phrase to a seed
pub fn mnemonic_to_seed(mnemonic: &[String], passphrase: &String) -> Vec<u8> {
    let mnemonic_phrase = mnemonic.join(" ");
    let salt = format!("mnemonic{}", passphrase);
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(
        mnemonic_phrase.as_bytes(),
        salt.as_bytes(),
        2048,
        &mut seed,
    )
    .expect("PBKDF2 derivation failed");
    seed.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bytes_to_hex, hex_to_bytes};
    use crate::bip32::*;

    #[test]
    fn test_mnemonic_to_seed() {
        let entropy = [0u8; 32];
        let mnemonic_words = generate_mnemonic_from_salt(&entropy);
        let seed = mnemonic_to_seed(&mnemonic_words, &"password".to_string());

        assert_eq!(seed.len(), 64, "Seed should be 64 bytes");
        assert_eq!(
            bytes_to_hex(&seed.as_slice(), false),
            "6226705e713f303e6bcd9750e1996b9f5dfa6fb842ab3887e9ee9302623832be79eca3dd73fc1100da30542700a8fecd4accb62cd4e930622dcd835cf00e2c15"
        );
    }

    #[test]
    #[should_panic(expected = "Invalid salt length. Must be 16, 20, 24, 28, or 32 bytes.")]
    fn test_invalid_salt_length() {
        let invalid_salt = [0u8; 15]; // Invalid length
        generate_mnemonic_from_salt(&invalid_salt);
    }

    #[test]
    fn test_trezor_vectors() {
        // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        let salt_hex = "0000000000000000000000000000000000000000000000000000000000000000";
        let salt = hex_to_bytes(salt_hex).unwrap();
        let mnemonic_words = generate_mnemonic_from_salt(&salt);
        let seed = mnemonic_to_seed(&mnemonic_words, &"TREZOR".to_string());
        let master_key = generate_master_key(&seed);
        assert_eq!(
            mnemonic_words.join(" "),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        );
        assert_eq!(
            bytes_to_hex(&seed.as_slice(), false),
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        );
        assert_eq!(
            master_key.to_base58_prv(),
            "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"
        );
    }
}
