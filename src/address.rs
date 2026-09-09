use sha2::Digest;
use ripemd::Ripemd160;

#[allow(dead_code)]
/// Generate a Bitcoin address (legacy P2PKH format) from a public key (compressed 33 bytes)
fn to_p2pkh(pub_key_bytes: &[u8]) -> String {
    let sha_hash = sha2::Sha256::digest(pub_key_bytes); // SHA-256 --> 32 bytes
    let ripemd_hash = Ripemd160::digest(&sha_hash); // RIPEMD-160 --> 20 bytes

    // Add prefix byte (0x00 for mainnet) to the RIPEMD-160 hash
    let mut payload = vec![0x00];
    payload.extend_from_slice(&ripemd_hash);

    bs58::encode(payload).with_check().into_string()
}

/// Generate compressed WIF private key from private key bytes (32 bytes)
pub fn to_wif_compressed(private_key_bytes: &[u8]) -> String {
    let mut payload = vec![0x80]; // prefix for mainnet
    payload.extend_from_slice(&private_key_bytes);
    payload.push(0x01); // compressed flag
    bs58::encode(payload).with_check().into_string()
}

/// Generate uncompressed WIF private key from private key bytes (32 bytes)
pub fn to_wif_uncompressed(private_key_bytes: &[u8]) -> String {
    let mut payload = vec![0x80]; // prefix for mainnet
    payload.extend_from_slice(&private_key_bytes);
    bs58::encode(payload).with_check().into_string()
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::*;

    #[test]
    fn test_to_wif_compressed() {
        // Test with known private keys and expected WIFs
        // https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

        let priv_key_hexes = [
            "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
            "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE"
        ];
        let expected_wifs = [
            "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
            "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7"
        ];

        for (priv_key_hex, expected_wif) in priv_key_hexes.iter().zip(expected_wifs.iter()) {
            let priv_key_bytes = hex_to_bytes(priv_key_hex).unwrap();
            let wif = to_wif_compressed(&priv_key_bytes);
            assert_eq!(wif, *expected_wif);
        }
    }

    #[test]
    fn test_to_wif_uncompressed() {
        // Test with known private keys and expected WIFs
        // https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

        let priv_key_hexes = [
            "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
            "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE"
        ];
        let expected_wifs = [
            "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
            "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5"
        ];

        for (priv_key_hex, expected_wif) in priv_key_hexes.iter().zip(expected_wifs.iter()) {
            let priv_key_bytes = hex_to_bytes(priv_key_hex).unwrap();
            let wif = to_wif_uncompressed(&priv_key_bytes);
            assert_eq!(wif, *expected_wif);
        }
    }

    #[test]
    fn test_to_p2pkh() {
        // Test with known public keys and expected addresses
        // https://www.scribd.com/document/820649235/found1

        let pub_key_hexes = [
            "0000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000a",
            "000000000000000000000000000000000000000e",
        ];

        let expected_addresses = [
            "1EXCN4m6mNL88QzPwksBnpVqr5F1dC4SGa",
            "1PhNVMTPDk4g23Xb6euCwTmyDGgxs18T8T",
            "1DUr3W3Q2ZHjU5DzNdApPwtrgf4XNSdkbT",
        ];

        for (pub_key_hex, expected_address) in pub_key_hexes.iter().zip(expected_addresses.iter()) {
            let pub_key_bytes = hex_to_bytes(pub_key_hex).unwrap();
            let address = to_p2pkh(&pub_key_bytes);
            assert_eq!(address, *expected_address);
        }
    }
}
