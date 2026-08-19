use bitcoin_insights::bip39::*;
use bitcoin_insights::{bytes_to_hex, random_salt};

fn main() {
    let salt = random_salt(16);

    let salt_hex = bytes_to_hex(&salt, true);
    println!("Generated random salt (16 bytes): {}", salt_hex);

    let mnemonic = generate_mnemonic_from_salt(&salt, Languages::English);
    println!("\nGenerated mnemonic: {:?}", mnemonic);

    let seed = mnemonic_to_seed(&mnemonic, &"password".to_string());
    let seed_hex = bytes_to_hex(&seed, true);
    println!("\nDerived seed (64 bytes): {}", seed_hex);

    // Example in Chinese
    let salt_chinese = random_salt(16);
    let salt_hex_chinese = bytes_to_hex(&salt_chinese, true);
    println!("\nGenerated random salt (16 bytes) for Chinese mnemonic: {}", salt_hex_chinese);
    let mnemonic_chinese = generate_mnemonic_from_salt(&salt_chinese, Languages::ChineseSimplified);
    println!("\nGenerated Chinese mnemonic: {:?}", mnemonic_chinese);
}
