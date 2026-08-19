// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::Group;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{Scalar, elliptic_curve::PrimeField};
use sha2::Sha512;

use crate::crypto::get_compressed_pubkey;
use crate::crypto::hash160;

type HmacSha512 = Hmac<Sha512>;

const HARDENED_OFFSET: u32 = 0x8000_0000; // 2^31

#[derive(Debug, Clone)]
pub struct ExtendedPrivKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],  // 32 bytes for the chain code
    pub private_key: [u8; 32], // 32 bytes for the private key
}

pub struct ExtendedPubKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32], // 32 bytes for the chain code
    pub public_key: [u8; 33], // 33 bytes for the compressed public key
}

impl ExtendedPrivKey {
    pub fn get_public_key(&self) -> [u8; 33] {
        get_compressed_pubkey(&self.private_key)
    }

    /// Convert ExtendedPrivKey to ExtendedPubKey
    pub fn to_extended_pub(&self) -> ExtendedPubKey {
        ExtendedPubKey {
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            chain_code: self.chain_code,
            public_key: self.get_public_key(),
        }
    }

    pub fn to_base58_prv(&self) -> String {
        let mut data = [0u8; 78];

        // Version bytes for mainnet extended private key (xprv)
        data[0..4].copy_from_slice(&[0x04, 0x88, 0xAD, 0xE4]); // 0x0488ADE4 private

        data[4] = self.depth;

        // the fingerprint of the parent's key (0x00000000 if master key)
        data[5..9].copy_from_slice(&self.parent_fingerprint);

        // child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized.
        // (0x00000000 if master key)
        data[9..13].copy_from_slice(&self.child_number.to_be_bytes());

        data[13..45].copy_from_slice(&self.chain_code);

        // private key data
        data[45] = 0x00; // Padding byte for private key
        data[46..78].copy_from_slice(&self.private_key);

        bs58::encode(data).with_check().into_string()
    }

    pub fn to_base58_pub(&self) -> String {
        let mut data = [0u8; 78];

        // Version bytes for mainnet extended public key (xpub)
        data[0..4].copy_from_slice(&[0x04, 0x88, 0xB2, 0x1E]); // 0x0488B21E public

        data[4] = self.depth;

        // the fingerprint of the parent's key (0x00000000 if master key)
        data[5..9].copy_from_slice(&self.parent_fingerprint);

        // child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized.
        // (0x00000000 if master key)
        data[9..13].copy_from_slice(&self.child_number.to_be_bytes());

        data[13..45].copy_from_slice(&self.chain_code);

        // public key data
        data[45..78].copy_from_slice(&self.get_public_key());

        bs58::encode(data).with_check().into_string()
    }
}

/// Calculate child private key k_i = (I_L + k_par) mod n
/// Return None if the resulting key is invalid (I_L >= n or k_i = 0).
/// else return Some(child_private_key).
fn calculate_child_private_key(par_priv_key: &[u8; 32], i_l_bytes: &[u8; 32]) -> Option<[u8; 32]> {
    // Because the private key is already a valid scalar, we can safely convert it to a Scalar type.
    let k_par: Scalar = Option::from(Scalar::from_repr((*par_priv_key).into()))
        .expect("Parent private key must be valid");

    // Convert I_L bytes to a Scalar. If the conversion fails (I_L >= n), return None.
    let i_l_opt: Option<Scalar> = Scalar::from_repr((*i_l_bytes).into()).into();
    let i_l = match i_l_opt {
        Some(scalar) => scalar,
        None => {
            return None;
        }
    };

    // k_i = (I_L + k_par) mod n
    let k_i: Scalar = i_l + k_par;

    // Check if k_i is zero (invalid key), if so, return None to indicate the index is invalid.
    let is_zero: bool = k_i.is_zero().into();
    if is_zero {
        return None;
    }

    let k_i_bytes = k_i.to_bytes();

    let mut result = [0u8; 32];
    result.copy_from_slice(&k_i_bytes);

    Some(result)
}

/// Calculate child public key K_i = G * I_L + K_par
/// Return None if the resulting key is invalid (I_L >= n or resulting point is at infinity).
/// else return Some(child_public_key).
fn calculate_child_public_key(k_par: &[u8; 33], i_l: &[u8; 32]) -> Option<[u8; 33]> {
    // If parse256(I_L) >= n or resulting point is at infinity, the resulting child key is invalid.
    let i_l_scalar_opt: Option<Scalar> = Scalar::from_repr((*i_l).into()).into();
    let i_l_scalar = match i_l_scalar_opt {
        Some(scalar) => scalar,
        None => {
            return None; // I_L >= n, invalid child key
        }
    };

    // Convert K_par to a k256::PublicKey
    let k_par_point = match k256::PublicKey::from_sec1_bytes(k_par) {
        Ok(pk) => pk,
        Err(_) => {
            return None; // Invalid parent public key
        }
    };

    // Calculate the new public key point: K_i = G * I_L + K_par
    let g = k256::ProjectivePoint::generator();
    let i_l_point = g * i_l_scalar; // G * I_L
    let k_par_point_proj = k_par_point.to_projective();
    let k_i_point = i_l_point + k_par_point_proj; // K_i = G * I_L + K_par

    // Check if the resulting point is at infinity (invalid child key)
    if k_i_point.is_identity().into() {
        return None; // Resulting point is at infinity, invalid child key
    }

    // Convert the resulting point back to a compressed public key
    let k_i_pubkey =
        k256::PublicKey::from_affine(k_i_point.to_affine()).expect("Valid public key point");
    let k_i_bytes = k_i_pubkey
        .to_sec1_point(true)
        .as_bytes()
        .try_into()
        .expect("Compressed public key must be 33 bytes");

    Some(k_i_bytes)
}

/// Generates a master extended private key from a seed using HMAC-SHA512.
/// Returns an ExtendedPrivKey struct
pub fn generate_master_key(seed: &[u8]) -> ExtendedPrivKey {
    let mut mac =
        HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC can take key of any size");
    mac.update(seed);
    let result = mac.finalize();
    let result_bytes = result.into_bytes();

    let mut private_key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    private_key.copy_from_slice(&result_bytes[..32]);
    chain_code.copy_from_slice(&result_bytes[32..]);

    ExtendedPrivKey {
        depth: 0,
        parent_fingerprint: [0u8; 4],
        child_number: 0,
        chain_code,
        private_key,
    }
}

/// Private parent key → private child key
///
/// If the resulting child private key is invalid (I_L >= n or k_i = 0), it returns None,
/// indicating that the index is invalid and one should proceed with the next index.
pub fn ckd_priv(parent: &ExtendedPrivKey, index: u32) -> Option<ExtendedPrivKey> {
    // Prepare the 37-byte payload for HMAC-SHA512
    let mut payload = [0u8; 37];
    if index >= HARDENED_OFFSET {
        payload[0] = 0x00;
        payload[1..33].copy_from_slice(&parent.private_key);
    } else {
        payload[0..33].copy_from_slice(&parent.get_public_key());
    }

    let index_bytes = index.to_be_bytes();
    payload[33..37].copy_from_slice(&index_bytes);

    let mut mac =
        HmacSha512::new_from_slice(&parent.chain_code).expect("HMAC can take key of any size");
    mac.update(&payload);

    let i_bytes = mac.finalize().into_bytes();

    let mut i_l = [0u8; 32];
    let mut i_r = [0u8; 32];
    i_l.copy_from_slice(&i_bytes[0..32]);
    i_r.copy_from_slice(&i_bytes[32..64]);

    let child_private_key = match calculate_child_private_key(&parent.private_key, &i_l) {
        Some(key) => key,
        None => {
            // If k_i is invalid, the chain is discarded, and the software should automatically
            // try with index + 1.
            return None;
        }
    };

    // Calculate Parent Fingerprint (first 4 bytes of hash160(Parent_PubKey))
    let hash160 = hash160(&parent.get_public_key());
    let hash160_bytes: &[u8] = hash160.as_ref();

    let mut parent_fingerprint = [0u8; 4];
    parent_fingerprint.copy_from_slice(&hash160_bytes[0..4]);

    Some(ExtendedPrivKey {
        depth: parent.depth + 1,
        parent_fingerprint,
        child_number: index,
        chain_code: i_r, // The new chain code is the right half I_R
        private_key: child_private_key,
    })
}

/// Public parent key → public child key
///
/// If the resulting child public key is invalid (I_L >= n or k_i = 0), it returns None,
/// indicating that the index is invalid and one should proceed with the next index.
pub fn ckd_pub(parent: &ExtendedPubKey, index: u32) -> Option<ExtendedPubKey> {
    if index >= HARDENED_OFFSET {
        // Cannot derive hardened child public key from parent public key
        panic!("Deriving index out of bounds");
    }

    // Payload = serP(K_par) || ser32(i)
    let mut payload = [0u8; 37];
    payload[0..33].copy_from_slice(&parent.public_key);
    let index_bytes = index.to_be_bytes();
    payload[33..37].copy_from_slice(&index_bytes);

    let mut mac =
        HmacSha512::new_from_slice(&parent.chain_code).expect("HMAC can take key of any size");
    mac.update(&payload);

    let i_bytes = mac.finalize().into_bytes();

    let mut i_l = [0u8; 32];
    let mut i_r = [0u8; 32];
    i_l.copy_from_slice(&i_bytes[0..32]);
    i_r.copy_from_slice(&i_bytes[32..64]);

    let child_public_key = match calculate_child_public_key(&parent.public_key, &i_l) {
        Some(key) => key,
        None => {
            // If K_i is invalid, the chain is discarded, and the software should automatically
            // try with index + 1.
            return None;
        }
    };

    // Calculate Parent Fingerprint (first 4 bytes of hash160(Parent_PubKey))
    let hash160 = hash160(&parent.public_key);
    let hash160_bytes: &[u8] = hash160.as_ref();

    let mut parent_fingerprint = [0u8; 4];
    parent_fingerprint.copy_from_slice(&hash160_bytes[0..4]);

    Some(ExtendedPubKey {
        depth: parent.depth + 1,
        parent_fingerprint,
        child_number: index,
        chain_code: i_r, // The new chain code is the right half I_R
        public_key: child_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::*;
    use crate::random_salt;
    use crate::hex::hex_to_bytes;

    #[test]
    fn test_generate_master_key() {
        let entropy = random_salt(32);
        let mnemonic_words = generate_mnemonic_from_salt(&entropy);
        let seed = mnemonic_to_seed(&mnemonic_words, &"password".to_string());
        let master_key = generate_master_key(&seed);

        assert_eq!(master_key.depth, 0);
        assert_eq!(master_key.parent_fingerprint, [0u8; 4]);
        assert_eq!(master_key.child_number, 0);
        assert_eq!(master_key.chain_code.len(), 32);
        assert_eq!(master_key.private_key.len(), 32);
    }

    #[test]
    fn test_ckd_pub_matches_ckd_priv() {
        // Test that deriving a non-hardened child from public key gives the same result
        // as deriving from private key and converting to public key
        let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
        let seed_bytes = hex_to_bytes(&seed).unwrap();
        let master_key = generate_master_key(&seed_bytes);
        
        // Derive non-hardened child from private key
        let child_priv = ckd_priv(&master_key, 0).unwrap();
        let child_pub_from_priv = child_priv.to_extended_pub();
        
        // Derive non-hardened child from public key
        let master_pub = master_key.to_extended_pub();
        let child_pub_from_pub = ckd_pub(&master_pub, 0).unwrap();
        
        // They should match
        assert_eq!(child_pub_from_priv.public_key, child_pub_from_pub.public_key);
        assert_eq!(child_pub_from_priv.chain_code, child_pub_from_pub.chain_code);
        assert_eq!(child_pub_from_priv.depth, child_pub_from_pub.depth);
        assert_eq!(child_pub_from_priv.parent_fingerprint, child_pub_from_pub.parent_fingerprint);
        assert_eq!(child_pub_from_priv.child_number, child_pub_from_pub.child_number);
    }

    #[test]
    #[should_panic(expected = "Deriving index out of bounds")]
    fn test_ckd_pub_hardened_should_panic() {
        // Test that trying to derive hardened child from public key should panic
        let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
        let seed_bytes = hex_to_bytes(&seed).unwrap();
        let master_key = generate_master_key(&seed_bytes);
        let master_pub = master_key.to_extended_pub();
        
        // This should panic
        ckd_pub(&master_pub, HARDENED_OFFSET);
    }

    #[test]
    fn test_vector_1() {
        // Test vector 1 from BIP32
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Test_vector_1
        let seed = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex_to_bytes(&seed).unwrap();
        let master_key = generate_master_key(&seed_bytes);

        assert_eq!(
            master_key.to_base58_prv(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );
        assert_eq!(
            master_key.to_base58_pub(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );

        // Chain m/0H
        let child_key = ckd_priv(&master_key, HARDENED_OFFSET + 0).unwrap();
        assert_eq!(
            child_key.to_base58_prv(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        );
        assert_eq!(
            child_key.to_base58_pub(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        );

        // Chain m/0H/1
        let child_key_1 = ckd_priv(&child_key, 1).unwrap();
        assert_eq!(
            child_key_1.to_base58_prv(),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
        );
        assert_eq!(
            child_key_1.to_base58_pub(),
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        );

        // Chain m/0H/1/2H
        let child_key_2 = ckd_priv(&child_key_1, HARDENED_OFFSET + 2).unwrap();
        assert_eq!(
            child_key_2.to_base58_prv(),
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
        );
        assert_eq!(
            child_key_2.to_base58_pub(),
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
        );

        // Chain m/0H/1/2H/2
        let child_key_3 = ckd_priv(&child_key_2, 2).unwrap();
        assert_eq!(
            child_key_3.to_base58_prv(),
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
        );
        assert_eq!(
            child_key_3.to_base58_pub(),
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
        );

        // Chain m/0H/1/2H/2/1000000000
        let child_key_4 = ckd_priv(&child_key_3, 1000000000).unwrap();
        assert_eq!(
            child_key_4.to_base58_prv(),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
        );
        assert_eq!(
            child_key_4.to_base58_pub(),
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        );
    }

    #[test]
    fn test_vector_2() {
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Test_vector_2
        let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"; // Example seed
        let seed_bytes = hex_to_bytes(&seed).unwrap();

        // Chain m
        let master_key = generate_master_key(&seed_bytes);
        assert_eq!(
            master_key.to_base58_prv(),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        );
        assert_eq!(
            master_key.to_base58_pub(),
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        );

        // Chain m/0
        let child_key = ckd_priv(&master_key, 0).unwrap();
        assert_eq!(
            child_key.to_base58_prv(),
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        );
        assert_eq!(
            child_key.to_base58_pub(),
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
        );

        // Chain m/0/2147483647H
        let child_key_hardened = ckd_priv(&child_key, HARDENED_OFFSET + 2147483647).unwrap();
        assert_eq!(
            child_key_hardened.to_base58_prv(),
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
        );
        assert_eq!(
            child_key_hardened.to_base58_pub(),
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
        );

        // Chain m/0/2147483647H/1
        let child_key_hardened_1 = ckd_priv(&child_key_hardened, 1).unwrap();
        assert_eq!(
            child_key_hardened_1.to_base58_prv(),
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
        );
        assert_eq!(
            child_key_hardened_1.to_base58_pub(),
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
        );

        // Chain m/0/2147483647H/1/2147483646H
        let child_key_hardened_2 =
            ckd_priv(&child_key_hardened_1, HARDENED_OFFSET + 2147483646).unwrap();
        assert_eq!(
            child_key_hardened_2.to_base58_prv(),
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
        );
        assert_eq!(
            child_key_hardened_2.to_base58_pub(),
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
        );

        // Chain m/0/2147483647H/1/2147483646H/2
        let child_key_hardened_3 = ckd_priv(&child_key_hardened_2, 2).unwrap();
        assert_eq!(
            child_key_hardened_3.to_base58_prv(),
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
        );
        assert_eq!(
            child_key_hardened_3.to_base58_pub(),
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        );
    }
}
