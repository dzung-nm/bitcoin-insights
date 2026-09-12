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
    fn test_a_simple_verify() {
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
    fn test_verify_success() {
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
    fn test_verify_fail() {
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
}
