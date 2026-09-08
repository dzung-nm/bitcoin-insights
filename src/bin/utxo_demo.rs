use k256::ecdsa::{SigningKey, signature::Signer};
use k256::elliptic_curve::Generate;
use rand::rngs::ThreadRng;

use bitcoin_insights::{compute_txid, hash160, Opcode, UtxoVerifier};

fn main() {
    let serialized_transaction = "0100000001abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789000000006a47304402207e2f3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b02203c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b012103abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ffffffff01abcdef012345678900000000";
    let tx_hash = compute_txid(serialized_transaction.as_bytes());

    let mut thread_rng = ThreadRng::default();
    let signing_key = SigningKey::generate_from_rng(&mut thread_rng);

    let verifying_key = signing_key.verifying_key();
    let pubkey = verifying_key.to_sec1_bytes().to_vec();
    let pubkey_hash = Vec::from(hash160(&pubkey));

    let signature: k256::ecdsa::Signature = signing_key.sign(&tx_hash);
    let mut sig = signature.to_der().as_bytes().to_vec();
    sig.push(0x01);

    let script_sig = vec![
        Opcode::OpPushData(sig),
        Opcode::OpPushData(pubkey),
    ];

    let script_pubkey = vec![
        Opcode::OpDup,
        Opcode::OpHash160,
        Opcode::OpPushData(pubkey_hash),
        Opcode::OpEqualVerify,
        Opcode::OpCheckSig,
    ];

    match UtxoVerifier::verify(&script_sig, &script_pubkey, &tx_hash) {
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
