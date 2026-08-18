use bitcoin_insights::bip32::*;
use bitcoin_insights::hex_to_bytes;

fn main() {
    let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
    let seed_bytes = hex_to_bytes(&seed).unwrap();
    let master_key = generate_master_key(&seed_bytes);

    println!("Master key: {:?}", master_key);
}
