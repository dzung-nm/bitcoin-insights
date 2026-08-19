use bitcoin_insights::bip39::*;
use bitcoin_insights::{bytes_to_hex, random_salt};

fn main() {
    let salt = random_salt(16);

    let salt_hex = bytes_to_hex(&salt, true);
    println!("Generated random salt (16 bytes): {}", salt_hex);

    let mnemonic = generate_mnemonic_from_salt(&salt);
    println!("\nGenerated mnemonic: {:?}", mnemonic);

    let seed = mnemonic_to_seed(&mnemonic, &"password".to_string());
    let seed_hex = bytes_to_hex(&seed, true);
    println!("\nDerived seed (64 bytes): {}", seed_hex);
}
