use nano_bitcoin::bip39::*;

fn main() {
    let cryptographic_salt = create_random_salt();

    let mnemonic = generate_mnemonic_from_salt(&cryptographic_salt);
    println!("\nGenerated mnemonic: {:?}", mnemonic);
}
