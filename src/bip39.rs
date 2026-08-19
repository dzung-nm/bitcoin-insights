// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader};

pub enum Languages {
    English,
    ChineseSimplified,
}

/// Get the bit at position i from the byte array data
fn get_bit(data: &[u8], i: usize) -> u8 {
    (data[i / 8] >> (7 - (i % 8))) & 1
}

/// Read mnemonic words from the english.txt file
fn read_mnemonic_words(lang: Languages) -> Vec<String> {
    let file = match lang {
        Languages::English => {
            File::open("src/mnemonic/english.txt").expect("Failed to open english.txt")
        }
        Languages::ChineseSimplified => File::open("src/mnemonic/chinese_simplified.txt")
            .expect("Failed to open chinese_simplified.txt"),
    };
    let reader = BufReader::new(file);
    reader
        .lines()
        .map(|line| line.expect("Failed to read line"))
        .filter(|line| !line.is_empty())
        .collect()
}

/// Generate a mnemonic phrase from a given salt
pub fn generate_mnemonic_from_salt(salt: &[u8], language: Languages) -> Vec<String> {
    // Valid salt lengths are 16, 20, 24, 28, or 32 bytes (128, 160, 192, 224, or 256 bits)
    if ![16, 20, 24, 28, 32].contains(&salt.len()) {
        panic!("Invalid salt length. Must be 16, 20, 24, 28, or 32 bytes.");
    }

    let mnemonic_words = read_mnemonic_words(language);

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
    use crate::bip32::*;
    use crate::{bytes_to_hex, hex_to_bytes};

    #[test]
    fn test_mnemonic_to_seed() {
        let entropy = [0u8; 32];
        let mnemonic_words = generate_mnemonic_from_salt(&entropy, Languages::English);
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
        generate_mnemonic_from_salt(&invalid_salt, Languages::English);
    }

    #[test]
    fn test_trezor_vectors_english() {
        // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        let data = vec![
            [
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
                "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq",
            ],
            [
                "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
                "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq",
            ],
            [
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
                "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd",
            ],
            [
                "000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
                "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
                "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
                "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
                "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7",
            ],
            [
                "808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
                "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
                "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae",
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
                "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
                "xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm",
            ],
            [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
                "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
                "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
                "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU",
            ],
            [
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
                "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
                "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo",
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
                "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
                "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB",
            ],
            [
                "9e885d952ad362caeb4efe34a8e91bd2",
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
                "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH",
            ],
            [
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
                "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
                "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK",
            ],
            [
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
                "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
                "xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk",
            ],
            [
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "scheme spot photo card baby mountain device kick cradle pact join borrow",
                "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
                "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6",
            ],
            [
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
                "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
                "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt",
            ],
            [
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
                "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
                "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems",
            ],
            [
                "23db8160a31d3e0dca3688ed941adbf3",
                "cat swing flag economy stadium alone churn speed unique patch report train",
                "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
                "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ",
            ],
            [
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
                "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
                "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh",
            ],
            [
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
                "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
                "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm",
            ],
            [
                "f30f8c1da665478f49b001d94c5fc452",
                "vessel ladder alter error federal sibling chat ability sun glass valve picture",
                "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
                "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps",
            ],
            [
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
                "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
                "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX",
            ],
            [
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
                "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS",
            ],
        ];

        for record in data {
            let salt = hex_to_bytes(record[0]).unwrap();
            let mnemonic_words = generate_mnemonic_from_salt(&salt, Languages::English);
            let seed = mnemonic_to_seed(&mnemonic_words, &"TREZOR".to_string());
            let master_key = generate_master_key(&seed);
            assert_eq!(mnemonic_words.join(" "), record[1]);
            assert_eq!(bytes_to_hex(&seed.as_slice(), false), record[2]);
            assert_eq!(master_key.to_base58_prv(), record[3]);
        }
    }

    #[test]
    fn test_trezor_vectors_chinese_simplified() {
        // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        let data = vec![
            [
                "00000000000000000000000000000000",
                "的 的 的 的 的 的 的 的 的 的 的 在",
                "7f7c7f91ef81f0fb6a3b95b346c50e6472c1d554f8ba90637bad8afce4a4de87c322c1acafa2f6f5e9a8f9b2d2c40e9d389efdc2adbe4445c21a0939fb39e91f",
                "xprv9s21ZrQH143K2LTAgxJMxVMKie6n9HQHMUohP6x2cx1TVBr6dxnL3mnSLRiXjiCM7g2ZF3BHzpdbFuhdeh7ZRrzv2EEjg5Tv7kgKZrqbVLc"
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 卿",
                "816a69d6866891b246b4d33f54d6d2be624470141754396205d039bdd8003949fec4340253dde4c8e11437a181ad992f56d5b976eb9fbe48f4c5e5fec60a27e1",
                "xprv9s21ZrQH143K2t2fMBqtVAVWU3JSpmEbbddwouLX8NoBbcTykD1Tm4s9api6K9zvoKSESUsA7aVxbZRunM5yrjZRNZnZckve98hxUorv2Uv"
            ],
            [
                "80808080808080808080808080808080",
                "壤 对 据 人 三 谈 我 表 壤 对 据 不",
                "07b6eada2601141ef9748bdf5af296a134f0f9215a946813b84338dcfba93c8247b0c3429a91e0a1b85a93bd9f1275a9524acecadc9b516c3cf4c8990f44052c",
                "xprv9s21ZrQH143K2cgeQUKgCSmaRVXFjEGThqrnNFmH71qG8z3bWqYcbX9zakkRxmDp583tqf3cQzmxtn4C2XqinMNb2HkhXBDYhekCB8AwZWV"
            ],
            [
                "ffffffffffffffffffffffffffffffff",
                "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 逻",
                "08ac5d9bed9441013b32bc317aaddeb8310011f219b48239faa4adeeb8b79cb0a3e4d1cb460d2dd37888c0a19bef6edd90ced0fd613d48899eab9ee649d77fcd",
                "xprv9s21ZrQH143K3Zkkh1w8EbXYQWAS5ekbitA2WVrswJY9uEJzig2BtairT72n98ySwQUAhYBsLW9EBjJ1XUinrSb69Ty4mttMLnaUooJwsJ3"
            ],
            [
                "000000000000000000000000000000000000000000000000",
                "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 动",
                "b8fb8047e84951d846dbfbbce3edd0c9e316dc40f35b39f03a837db85f5587ac209088e883b5d924a0a43ad154a636fb65df28fdae821226f0f014a49e773356",
                "xprv9s21ZrQH143K36LufUjTLqXnTiY6ach28pUYMkJ63swx4FhjPkzqD9YRqDZ452whYcNzKpPC8yfBm1eomL2z3VLC4zcwU71oKvMQ5NnD4h1"
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 殿",
                "74187bbdce2dba25eed3b9aebdc65dcb7c61e74c58591451d47f9c7b7b17545a527880640bfb9cab36989eba1edddf57bfce7340697926de7f0b9ec1e0345c38",
                "xprv9s21ZrQH143K47jLpKzSgdpMLSKP2ZMLXHHUqYYGKbXNE4k3TA2czvJCx5JAJFNkWKZf2B1AbYoUBpc96YoiwM7yfxyr8gvfNNgL7sFNum6"
            ],
            [
                "808080808080808080808080808080808080808080808080",
                "壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 民",
                "e3629a601f4b87101c4bb36496e3dbd146063351f5e47c048211faddab78efdb91910f0eea5c8e53cfb851aa3e156b0bb5c501b83baaf5f5d4a1679a5bb7d885",
                "xprv9s21ZrQH143K4RfeWihCeh1FJL9SobvinRW4z76RL2X1TB6xreXgaMvJGggUgagkaNr7zX47YHEDYdzJmig8SG3Scuet8smspn7HicCtwHa"
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 裕",
                "013c8d6868537176fac7bfa966e6219830008f03b650b0f18a12fd67d9ebf871c400c5f980aa073ddd1b23d60846e357aee193ce7644b574bf65e04cf913e39c",
                "xprv9s21ZrQH143K2YiskWzQq8kpFFCoFKKU4L8D6Y593dS2sExuVQ4GjnS57RhibwTWjnD7NTCE7ye4cQbCK6Bw674SHb3xWaQYH3NBLFCGYJb"
            ],
            [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 性",
                "1981c3e3ddfd80f6e9ee1c5ef27ba2697df3d1468496f1d56ae3d8e0b3f0677bbbdfca954e48eb86fe6a36fc0f597bf18ea00248757a01e82182badff94abbbd",
                "xprv9s21ZrQH143K25ttGBGbx6h9VBpa9ELbpw35XQqDR8deXRyVP2AbtgJ79Nq2cW8KaDizbwuoHUYR1o4tLPhYvSCTNMft4ZEfiDztmjXKPCj"
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 搭",
                "b1eb831927f1c488e233725f9c409dd9bdb9342324393fa56d958e8842623d222510c322f5ba2899428ae08ece8bd87788748c67bdfa73588669ab816c5f3555",
                "xprv9s21ZrQH143K4VNNDqCgnETDkPiihzHpxC9wGE6TBGXaeEd9VkQRHQPotwheeaNFGHGKaPWv5zTqfknzgdWiKFC6DqaqBFKjNSmxas968Vz"
            ],
            [
                "8080808080808080808080808080808080808080808080808080808080808080",
                "壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 五",
                "470e61f7e976fa18c7d559e842ba7f39849b2f72ef15428f4276c5160002f36416cd22c2a86bb686d69f6b91818538aa57ae1aab27b3181b92132c59be2b329b",
                "xprv9s21ZrQH143K3bUoGmLq8aXRKzvUhseqrXw1t7XYCirduP5XLJtVxCos3rYLDvW8V7pK3voZ4EWSdeXiKdbWNjxmiPRDfet23Av9VRaR3ej"
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 佳",
                "8e6607a07fa664d6e4ead23fcc08caf72216d6f078c3b2e5be94e4b6e8d64c784d36bf9b70144fa05840e9a49899128111be5093a2b552b6ab76c0906e9b0e65",
                "xprv9s21ZrQH143K2ghKxX47TRr4GnQh3diJFN5rJfybjxuwr3xP6pafXrBhwXJsw4HwoiPZ1f6fFPR964eoXybV2su498Ant3kYuYKE3CszLsU"
            ],
            [
                "9e885d952ad362caeb4efe34a8e91bd2",
                "蒙 台 脱 纪 构 硫 浆 霉 感 仅 鱼 汤",
                "decd71d2824a1bbadf8c3942f43504a648a8db5f1cac0ae1d0f787728353002a12644b1a6b725147c91682e7f33aec13493b9a779a7dd8ee15a5d10ab21d49e5",
                "xprv9s21ZrQH143K44Xrktko35a7gPGVo91Va79LNer1MzVokcrYKFP6GMLAcuJP3fBSdbRuG2DauFC48H6LmyZLfkUyjpm1R2AxYVbnT2P5tur"
            ],
            [
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "父 泥 炼 胁 鞋 控 载 政 惨 逐 整 碗 环 惯 案 棒 订 移",
                "ff66373b70b72b34842f936bf3bb44d661fdafaee7740d574fed6aa2ef07783cb6111f2862cbd3fc5528e322dfe054557a74a568a1b46c020cb88938e2293ca0",
                "xprv9s21ZrQH143K3JLu5XeRDQA5RwHh6gUXaQfRf7ihtVguJvd6EFoAzsoyotvNTDZfC6cciies7fhcqaMRTEsZUSbRYqBdaviWRHatRMoHX6s"
            ],
            [
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "宁 照 违 材 交 养 违 野 悉 偷 梅 设 贵 帝 鲜 仰 圈 首 荷 钩 隙 抓 养 熟",
                "6ba622f907c61e29e44833b08441b7afa84889a48ca90ebf90f585e257662b2c1b0c35ad54088e745c73689921209fdd4b5b8ace5d850e366d7c2042a076e660",
                "xprv9s21ZrQH143K3dE2RQqFbapci6WBj47vZCkLVf4r14QsRZ6Ny2ck6s8tzZQzQaM55Tt4d2tRS9AuFrEJ4yBXsmP8yKeVGXT8E97iRVkDzCj"
            ],
            [
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "伐 旱 泡 口 线 揭 县 杨 断 芳 额 件",
                "7346996be5f2b02c67ec465c677197375b589b6e8871c842505b139c2d47feca75a2a941623d6486aff6b21c95193a8177960d123cf610f03f3224a9fa7d0eed",
                "xprv9s21ZrQH143K3A2p7cttKM5L39rutYgY4jqZ16z7hpAEdyiT8fr5eKdaHGLMM2ZmsUFNvGcSfyGMp1sz9nVyg3ZXop1hesUbgAvVBzx4rix"
            ],
            [
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "福 惜 怀 叔 筋 酵 货 科 牙 冒 辈 罩 悬 耕 浇 呵 连 级",
                "09098e00fcc1bfa7d5b9f0c12dfe1993bbd5a0915200a53fb40b2d6d487b969a18463565c1e035569796a7d8b99f82a4c4b17002b0c582037da95bacfeb422b3",
                "xprv9s21ZrQH143K4LdjFgCrosa76XBrNQ4imGB7XNc5MhfkASrmAHVNWYLNGY6kNj8foXBLS9aUD8RDubyj3NKWarmXxRQ28AeWVPbLD3a1FEq"
            ],
            [
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "仪 未 九 茶 队 梯 妇 孤 托 病 泉 贺 产 绘 吹 测 局 碳 征 墨 晶 帮 息 延",
                "6d55f2dd8d42f1cc5e0b4ef6e8a95200580ff4e29d2a3dfa7f9ddb1af0aa2e93780d84d952d39776a379ddc017847ea01aa01b85dc208e7f69891d5b7cbf2eb0",
                "xprv9s21ZrQH143K2tkCCjLXj2L9Ds9FttWwH6Eqt3uvihwUvpSpTm3RmRtSkapxASEUW5HXE6Qx2H1viBxXbLZVKxyfQ7fyFn6NcDspgJfdPaT"
            ],
            [
                "23db8160a31d3e0dca3688ed941adbf3",
                "济 扶 块 言 穗 定 万 绘 姻 逃 颗 焰",
                "bf8dcc2fb4dc8fd2311943b527864feabfebd5fffb6641555519da3606265e895bab5aa1647f6e5afb0cb6ea4d0b27e8a9f2f49251b68ad6bf898937581351cb",
                "xprv9s21ZrQH143K2i53x2geCJi6A2QJpaHpxeGK8oeMxYs1tUrUwU3ddu9jHVucF3ePQ1koQ1TVFHnfP21ScWzp8xKnMinNUSW5itm7PicXWYW"
            ],
            [
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "虑 铺 目 祸 英 钩 尤 添 醇 嘛 触 独 起 赋 连 剪 邦 中",
                "07e1a2dc2eea79bb12be53d6fb662edf87796cad60e8d10a655ba39a95c5a68eb21f865a1b2f37d780286adbbddeccba3f7844c8a2b1a82029e6a855c713aecf",
                "xprv9s21ZrQH143K4V2oh58ZSb1CAbYkwB6ThJmTpRC51uKha9hy51R6RVzzbcEog3n6h4u7FtotS9arBvLofX7A3Apvcaedmeg1jkt7Vkt9TtA"
            ],
            [
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "而 怕 夏 客 盖 古 松 面 解 谓 鲜 唯 障 烯 共 吴 永 丁 赤 副 醒 分 猛 埔",
                "0402ae511062cfacbd5e33637a95e57e2e14fde0c5dd471fe66fc1154b6373802aa8641a78b91658052bff0a5c5bd075f01fc74b0d73e95a890430ff6f0e728e",
                "xprv9s21ZrQH143K4LSoFcKBWtmUHjzuH56srzrkpPfGx3i36UXpVUEtGvCuZ3egRTyDkaqRN5Ec1HXvXGSGTXLyAKzCRnTspi1D9NdmQmWqM5x"
            ],
            [
                "f30f8c1da665478f49b001d94c5fc452",
                "昏 途 所 够 请 乃 风 一 雕 缺 垫 阀",
                "aa7e38f64810007db63e31c479b9848cd5ffda839546749669bf53476dd036a33fd77d0a13d4418fb536ea78b028fc19533db4bc9e0e12a14a9432cb9fd112a2",
                "xprv9s21ZrQH143K31afj91bWiGw2aC2xHJwrWsMs9MuvEWZETkpWr15ZNF6LFjkHh53iD2bwJYEawvCCvDRaqDsr37fhapgGDkA7UATtwBsZu3"
            ],
            [
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "瓶 顾 床 圈 倡 励 炭 柄 且 招 价 紧 折 将 乎 硬 且 空",
                "2a6181cf2b069ba30a87228d54770ed5abf61e8151abdb0b27646a87a6100d4b7b496c3ca26f027d0b06724c6c5a469f43a7f1ffb7782e5afb01d143ca65973d",
                "xprv9s21ZrQH143K3ji6aQ9QQi4WkFhAqnrzRANJkYkRWkMqbr51mAV6JYUt85oR8Jt3D7DreQdsb9292ips6VKwpitAhLR7rfLdhYz7zgYei2F"
            ],
            [
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "柄 需 固 姆 色 斥 霍 握 宾 琴 况 团 抵 经 摸 郭 沙 鸣 拖 妙 阳 辈 掉 迁",
                "4dccb0a3578716975b840c51e279c2af728567ff42e98dd09b9e61742b41d9f30d411a501172cce9b7d5706a480dd4d4e7fb26021a36a74381156b09d251d65a",
                "xprv9s21ZrQH143K2hLNNA7KnimwonwFXCiGVM3K29DgZiTcVUJ8t8jkc2mXUzFZmoFgXWh9UhJFbyKM44Qm2KeGsrEevajZZfKyoLyFmyoDpUx"
            ]
        ];

        for rec in data {
            let salt = hex_to_bytes(rec[0]).unwrap();
            let mnemonic_words = generate_mnemonic_from_salt(&salt, Languages::ChineseSimplified);
            let seed = mnemonic_to_seed(&mnemonic_words, &"TREZOR".to_string());
            let master_key = generate_master_key(&seed);
            assert_eq!(mnemonic_words.join(" "), rec[1]);
            assert_eq!(bytes_to_hex(&seed.as_slice(), false), rec[2]);
            assert_eq!(master_key.to_base58_prv(), rec[3]);
        }
    }
}