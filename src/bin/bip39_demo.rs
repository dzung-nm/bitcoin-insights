use bitcoin_insights::bip39::*;
use bitcoin_insights::random_salt;

fn main() {
    let cryptographic_salt = random_salt(32);

    let mnemonic = generate_mnemonic_from_salt(&cryptographic_salt);
    println!("\nGenerated mnemonic: {:?}", mnemonic);
}
