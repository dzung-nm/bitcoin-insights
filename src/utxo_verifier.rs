use crate::crypto::hash160;
use crate::k256::verify_signature;

#[derive(Debug, Clone, PartialEq)]
pub enum Opcode {
    OpPushData(Vec<u8>),
    OpDup,
    OpHash160,
    OpEqual,
    OpEqualVerify,
    OpCheckSig,
    OpAdd,
}

#[derive(Debug, PartialEq)]
pub enum VerificationError {
    StackUnderflow,
    VerifyFailed,
    InvalidScript,
    SignatureInvalid,
}

pub struct UtxoVerifier;

impl UtxoVerifier {
    /// Returns true if the transaction is valid, false otherwise.
    pub fn verify(
        script_sig: &[Opcode],
        script_pubkey: &[Opcode],
        tx_hash: &[u8; 32],
    ) -> Result<bool, VerificationError> {
        let mut stack: Vec<Vec<u8>> = Vec::new();

        // Execute the unlocking script (scriptSig) first, then the locking script (scriptPubKey)
        // DO NOT execute both scripts in a single pass; they must be executed sequentially.
        Self::execute_script(script_sig, tx_hash, &mut stack)?;
        Self::execute_script(script_pubkey, tx_hash, &mut stack)?;

        if let Some(top) = stack.last() {
            Ok(top != &[0] && !top.is_empty()) // Top stack item must be non-zero and non-empty for a valid transaction
        } else {
            Ok(false)
        }
    }

    fn execute_script(
        script: &[Opcode],
        tx_hash: &[u8; 32],
        stack: &mut Vec<Vec<u8>>,
    ) -> Result<(), VerificationError> {
        for op in script {
            match op {
                Opcode::OpAdd => {
                    let a = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let b = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let sum = a
                        .iter()
                        .zip(b.iter())
                        .map(|(x, y)| x.wrapping_add(*y))
                        .collect();
                    stack.push(sum);
                }

                Opcode::OpPushData(data) => {
                    stack.push(data.clone());
                }

                Opcode::OpDup => {
                    let top = stack.last().ok_or(VerificationError::StackUnderflow)?;
                    stack.push(top.clone());
                }

                Opcode::OpHash160 => {
                    let data = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let hashed = hash160(&data);
                    println!("{:?}", hashed);
                    stack.push(Vec::from(hashed));
                }

                Opcode::OpEqual => {
                    let a = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let b = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let res = if a == b { vec![1] } else { vec![0] };
                    stack.push(res);
                }

                Opcode::OpEqualVerify => {
                    let a = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let b = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    if a != b {
                        return Err(VerificationError::VerifyFailed);
                    }
                }

                Opcode::OpCheckSig => {
                    let pubkey = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let sig = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let verified = verify_signature(&pubkey, &sig, tx_hash);
                    stack.push(vec![if verified { 1 } else { 0 }]);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{SigningKey, signature::Signer};
    use k256::elliptic_curve::Generate;
    use rand::rngs::ThreadRng;

    #[test]
    fn test_op_checksig_success() {
        let mut thread_rng = ThreadRng::default();
        let signing_key = SigningKey::generate_from_rng(&mut thread_rng);

        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_sec1_bytes().to_vec();

        // Simulate a transaction hash for testing purposes
        let tx_hash: [u8; 32] = [0x42; 32];

        // Create a signature DER and append SIGHASH_ALL (0x01)
        let signature: k256::ecdsa::Signature = signing_key.sign(&tx_hash);
        let mut sig_bytes = signature.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        // Verify the signature using the public key and transaction hash
        assert!(verify_signature(&pubkey_bytes, &sig_bytes, &tx_hash));
    }

    #[test]
    fn test_simple_cases() {
        // 2 + 3 == 5 => 2 3 OP_ADD 5 OP_EQUAL
        let script_sig = vec![Opcode::OpPushData(vec![0x02])];

        let script_pubkey = vec![
            Opcode::OpPushData(vec![0x03]),
            Opcode::OpAdd,
            Opcode::OpPushData(vec![0x05]),
            Opcode::OpEqual,
        ];

        let tx_hash = [0x11; 32];
        let result = UtxoVerifier::verify(&script_sig, &script_pubkey, &tx_hash);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn test_p2pkh_mock_success() {
        let mut thread_rng = ThreadRng::default();
        let signing_key = SigningKey::generate_from_rng(&mut thread_rng);
        let verifying_key = signing_key.verifying_key();
        let mock_pubkey = verifying_key.to_sec1_bytes().to_vec();
        let tx_hash: [u8; 32] = [0x24; 32];
        let signature: k256::ecdsa::Signature = signing_key.sign(&tx_hash);
        let mut mock_sig = signature.to_der().as_bytes().to_vec();
        mock_sig.push(0x01);
        let mock_pubkey_hash = Vec::from(hash160(&mock_pubkey));

        let script_sig = vec![
            Opcode::OpPushData(mock_sig),
            Opcode::OpPushData(mock_pubkey),
        ];

        let script_pubkey = vec![
            Opcode::OpDup,
            Opcode::OpHash160,
            Opcode::OpPushData(mock_pubkey_hash),
            Opcode::OpEqualVerify,
            Opcode::OpCheckSig,
        ];

        let result = UtxoVerifier::verify(&script_sig, &script_pubkey, &tx_hash);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn test_p2pkh_mock_wrong_hash_fail() {
        let mock_sig = vec![0x11, 0x22, 0x33];
        let mock_pubkey = vec![0xAA, 0xBB, 0xCC];
        let wrong_pubkey_hash = vec![0x99, 0x00, 0x00, 0x00];
        let tx_hash = [0x33; 32];

        let script_sig = vec![
            Opcode::OpPushData(mock_sig),
            Opcode::OpPushData(mock_pubkey),
        ];

        let script_pubkey = vec![
            Opcode::OpDup,
            Opcode::OpHash160,
            Opcode::OpPushData(wrong_pubkey_hash),
            Opcode::OpEqualVerify,
            Opcode::OpCheckSig,
        ];

        let result = UtxoVerifier::verify(&script_sig, &script_pubkey, &tx_hash);
        assert_eq!(result, Err(VerificationError::VerifyFailed));
    }
}
