use crate::script::opcode::*;
use crate::script::script::*;

pub struct Transaction {
    pub tx_hash: [u8; 32],
}

#[derive(Debug, PartialEq)]
pub enum ExecutionError {
    StackUnderflow,
    VerifyFailed,
    SignatureInvalid,
    InvalidRedeemScript,
    ScriptHashMismatch,
}

impl Script {
    pub fn execute(
        &self,
        trans: &Transaction,
        stack: &mut Vec<Vec<u8>>,
    ) -> Result<bool, ExecutionError> {
        for op in &self.opcodes {
            match op {
                Opcode::OpPushData(data) => stack.push(data.clone()),
                Opcode::OpAdd => {
                    let a = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
                    let b = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
                    let sum = a
                        .iter()
                        .zip(b.iter())
                        .map(|(x, y)| x.wrapping_add(*y))
                        .collect();
                    stack.push(sum);
                }
                Opcode::OpDup => {
                    let top = stack.last().ok_or(ExecutionError::StackUnderflow)?.clone();
                    stack.push(top);
                }
                Opcode::OpHash160 => {
                    let top = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
                    let hash = crate::crypto::hash160(&top);
                    stack.push(hash.to_vec());
                }
                Opcode::OpEqual => {
                    let a = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
                    let b = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
                    if a == b {
                        stack.push(vec![1]);
                    } else {
                        stack.push(vec![0]);
                    }
                }
                Opcode::OpEqualVerify => {
                    let a = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
                    let b = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
                    if a != b {
                        return Err(ExecutionError::VerifyFailed);
                    }
                }
                Opcode::OpCheckSig => {
                    let pubkey = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
                    let sig = stack.pop().ok_or(ExecutionError::StackUnderflow)?;

                    if !crate::k256::verify_signature(&pubkey, &sig, &trans.tx_hash) {
                        return Err(ExecutionError::SignatureInvalid);
                    }

                    // If signature is valid, push 1 onto the stack
                    stack.push(vec![1]);
                }
                Opcode::OpN(n) => stack.push(vec![*n]),
                Opcode::OpCheckMultiSig => {
                    let n = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
                    let n_keys = *n.first().ok_or(ExecutionError::StackUnderflow)? as usize;

                    let mut pubkeys = Vec::with_capacity(n_keys);
                    for _ in 0..n_keys {
                        pubkeys.push(stack.pop().ok_or(ExecutionError::StackUnderflow)?);
                    }

                    let m = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
                    let m_sigs = *m.first().ok_or(ExecutionError::StackUnderflow)? as usize;

                    let mut sigs = Vec::with_capacity(m_sigs);
                    for _ in 0..m_sigs {
                        sigs.push(stack.pop().ok_or(ExecutionError::StackUnderflow)?);
                    }

                    // Historical off-by-one bug in Bitcoin: an extra dummy value is consumed.
                    stack.pop().ok_or(ExecutionError::StackUnderflow)?;

                    // Verify each signature against pubkeys in order (signatures and pubkeys
                    // must both be in the same relative order).
                    let mut key_idx = 0;
                    let mut valid_sigs = 0;
                    for sig in &sigs {
                        while key_idx < pubkeys.len() {
                            if crate::k256::verify_signature(&pubkeys[key_idx], sig, &trans.tx_hash) {
                                valid_sigs += 1;
                                key_idx += 1;
                                break;
                            }
                            key_idx += 1;
                        }
                    }

                    if valid_sigs >= m_sigs {
                        stack.push(vec![1]);
                    } else {
                        return Err(ExecutionError::SignatureInvalid);
                    }
                }
            }
        }

        // After executing the script, the top of the stack should be non-zero for a valid transaction
        if let Some(top) = stack.last() {
            Ok(top != &[0] && !top.is_empty())
        } else {
            Ok(false)
        }
    }
}

/// Validate a P2SH transaction by executing the redeem script and verifying the signature(s).
/// scriptSig format: <args...> <serialized_redeem_script>
/// scriptPubKey format: OP_HASH160 <20-byte-hash> OP_EQUAL
pub fn verify_p2sh(
    script_sig: &Script,
    script_pubkey: &Script,
    trans: &Transaction,
) -> Result<bool, ExecutionError> {
    // Execute scriptSig to get the stack. The top item must be the serialized redeem script.
    let mut stack: Vec<Vec<u8>> = Vec::new();
    script_sig.execute(trans, &mut stack)?;

    let redeem_script_bytes = stack.last().ok_or(ExecutionError::StackUnderflow)?.clone();

    // Execute scriptPubKey (OP_HASH160 <hash> OP_EQUAL) against the stack.
    // This verifies that HASH160(redeem_script) matches the embedded hash.
    script_pubkey.execute(trans, &mut stack)?;

    let hash_check = stack.pop().ok_or(ExecutionError::StackUnderflow)?;
    if hash_check == vec![0] || hash_check.is_empty() {
        return Err(ExecutionError::ScriptHashMismatch);
    }

    // Deserialize the redeem script and execute it with the remaining stack items (args).
    let redeem_script =
        Script::from_bytes(&redeem_script_bytes).map_err(|_| ExecutionError::InvalidRedeemScript)?;

    // The remaining stack items are the arguments for the redeem script.
    // (The redeem script itself has already been consumed by OP_EQUAL above.)
    redeem_script.execute(trans, &mut stack)?;

    if let Some(top) = stack.last() {
        Ok(top != &[0] && !top.is_empty())
    } else {
        Ok(false)
    }
}

#[allow(dead_code)]
/// Returns true if the transaction is valid, false otherwise.
pub fn verify_utxo(
    script_sig: &Script,
    script_pubkey: &Script,
    trans: &Transaction,
) -> Result<bool, ExecutionError> {
    let mut stack: Vec<Vec<u8>> = Vec::new();

    // Execute the unlocking script (scriptSig) first, then the locking script (scriptPubKey)
    // DO NOT execute both scripts in a single pass; they must be executed sequentially.
    script_sig.execute(&trans, &mut stack)?;
    script_pubkey.execute(&trans, &mut stack)?;

    if let Some(top) = stack.last() {
        Ok(top != &[0] && !top.is_empty())
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use rand::prelude::ThreadRng;
    use k256::ecdsa::{SigningKey, signature::Signer};
    use k256::elliptic_curve::Generate;

    use super::*;
    use crate::script::opcode::Opcode;
    use crate::script::script::Script;
    use crate::hash160;

    #[test]
    fn test_a_simple_verify_utxo() {
        // 2 + 3 == 5 => 2 3 OP_ADD 5 OP_EQUAL
        let script_sig = Script::new(vec![Opcode::OpPushData(vec![0x02])]);

        let script_pubkey = Script::new(vec![
            Opcode::OpPushData(vec![0x03]),
            Opcode::OpAdd,
            Opcode::OpPushData(vec![0x05]),
            Opcode::OpEqual,
        ]);

        let trans = Transaction { tx_hash: [0x11; 32] };
        let result = verify_utxo(&script_sig, &script_pubkey, &trans);

        assert_eq!(result, Ok(true));
    }

    #[test]
    fn test_verify_utxo_success() {
        let mut thread_rng = ThreadRng::default();
        let signing_key = SigningKey::generate_from_rng(&mut thread_rng);

        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_sec1_bytes().to_vec();
        let pubkey_hash = Vec::from(hash160(&pubkey));

        let tx_hash: [u8; 32] = [0x24; 32]; // Mock transaction hash
        let signature: k256::ecdsa::Signature = signing_key.sign(&tx_hash);
        let mut signature_bytes = signature.to_der().as_bytes().to_vec();
        signature_bytes.push(0x01); // Append SIGHASH_ALL byte

        let script_sig = Script::new(vec![
            Opcode::OpPushData(signature_bytes),
            Opcode::OpPushData(pubkey),
        ]);

        let script_pubkey = Script::new(vec![
            Opcode::OpDup,
            Opcode::OpHash160,
            Opcode::OpPushData(pubkey_hash),
            Opcode::OpEqualVerify,
            Opcode::OpCheckSig,
        ]);

        let trans = Transaction { tx_hash };
        let result = verify_utxo(&script_sig, &script_pubkey, &trans);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn test_verify_utxo_fail() {
        let mock_sig = vec![0x11, 0x22, 0x33];
        let mock_pubkey = vec![0xAA, 0xBB, 0xCC];
        let wrong_pubkey_hash = vec![0x99, 0x00, 0x00, 0x00];
        let tx_hash = [0x33; 32];

        let script_sig = Script::new(vec![
            Opcode::OpPushData(mock_sig),
            Opcode::OpPushData(mock_pubkey),
        ]);

        let script_pubkey = Script::new(vec![
            Opcode::OpDup,
            Opcode::OpHash160,
            Opcode::OpPushData(wrong_pubkey_hash),
            Opcode::OpEqualVerify,
            Opcode::OpCheckSig,
        ]);

        let trans = Transaction { tx_hash };
        let result = verify_utxo(&script_sig, &script_pubkey, &trans);
        assert_eq!(result, Err(ExecutionError::VerifyFailed));
    }

    #[test]
    fn test_verify_p2sh_success() {
        let mut thread_rng = ThreadRng::default();

        // Generate 3 key pairs for 2-of-3 multisig
        let signing_key1 = SigningKey::generate_from_rng(&mut thread_rng);
        let signing_key2 = SigningKey::generate_from_rng(&mut thread_rng);
        let signing_key3 = SigningKey::generate_from_rng(&mut thread_rng);

        let pubkey1 = signing_key1.verifying_key().to_sec1_bytes().to_vec();
        let pubkey2 = signing_key2.verifying_key().to_sec1_bytes().to_vec();
        let pubkey3 = signing_key3.verifying_key().to_sec1_bytes().to_vec();

        let tx_hash: [u8; 32] = [0x42; 32];

        // Sign with key1 and key2 (satisfying the 2-of-3 threshold)
        let sig1: k256::ecdsa::Signature = signing_key1.sign(&tx_hash);
        let mut sig1_bytes = sig1.to_der().as_bytes().to_vec();
        sig1_bytes.push(0x01); // SIGHASH_ALL

        let sig2: k256::ecdsa::Signature = signing_key2.sign(&tx_hash);
        let mut sig2_bytes = sig2.to_der().as_bytes().to_vec();
        sig2_bytes.push(0x01); // SIGHASH_ALL

        // redeem_script: OP_2 <PubKey1> <PubKey2> <PubKey3> OP_3 OP_CHECKMULTISIG
        let redeem_script = Script::new(vec![
            Opcode::OpN(2),
            Opcode::OpPushData(pubkey1),
            Opcode::OpPushData(pubkey2),
            Opcode::OpPushData(pubkey3),
            Opcode::OpN(3),
            Opcode::OpCheckMultiSig,
        ]);

        // scriptSig: OP_0 (dummy) <sig1> <sig2> <serialized_redeem_script>
        // The dummy element accounts for the historical off-by-one bug in OP_CHECKMULTISIG.
        let script_sig = Script::new(vec![
            Opcode::OpPushData(vec![]),   // OP_0 dummy
            Opcode::OpPushData(sig1_bytes),
            Opcode::OpPushData(sig2_bytes),
            Opcode::OpPushData(redeem_script.to_bytes()),
        ]);

        let script_pubkey = redeem_script.generate_p2sh_script();

        let trans = Transaction { tx_hash };
        let result = verify_p2sh(&script_sig, &script_pubkey, &trans);
        assert_eq!(result, Ok(true));
    }
}
