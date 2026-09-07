use bitcoin_insights::utxo_verifier::*;

fn main() {
    let script_sig = vec![
        Opcode::OpPushData(vec![0x01, 0x02, 0x03]), // Signature
        Opcode::OpPushData(vec![0x04, 0x05, 0x06]), // Public key
    ];

    let public_key_hash = vec![97, 27, 29, 204, 51, 5, 239, 104, 230, 117, 137, 124, 87, 155, 79, 240, 14, 193, 216, 33]; // Example public key hash

    let script_pubkey = vec![
        Opcode::OpDup,
        Opcode::OpHash160,
        Opcode::OpPushData(public_key_hash),
        Opcode::OpEqualVerify,
        Opcode::OpCheckSig,
    ];

    match UtxoVerifier::verify(&script_sig, &script_pubkey) {
        Ok(valid) => {
            if valid {
                println!("Transaction is valid!");
            } else {
                println!("Transaction is invalid!");
            }
        }
        Err(e) => {
            println!("Verification error: {:?}", e);
        }
    }
}
