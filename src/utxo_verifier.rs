use crate::crypto::hash160;

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
    pub fn verify(script_sig: &[Opcode], script_pubkey: &[Opcode]) -> Result<bool, VerificationError> {
        let mut stack: Vec<Vec<u8>> = Vec::new();

        // Execute the unlocking script (scriptSig) first, then the locking script (scriptPubKey)
        // DO NOT execute both scripts in a single pass; they must be executed sequentially.
        Self::execute_script(script_sig, &mut stack)?;
        Self::execute_script(script_pubkey, &mut stack)?;

        if let Some(top) = stack.last() {
            Ok(top != &[0] && !top.is_empty()) // Top stack item must be non-zero and non-empty for a valid transaction
        } else {
            Ok(false)
        }
    }

    fn execute_script(script: &[Opcode], stack: &mut Vec<Vec<u8>>) -> Result<(), VerificationError> {
        for op in script {
            match op {
                Opcode::OpAdd => {
                    let a = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let b = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let sum = a.iter().zip(b.iter()).map(|(x, y)| x.wrapping_add(*y)).collect();
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
                    let _pubkey = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    let _sig = stack.pop().ok_or(VerificationError::StackUnderflow)?;
                    // TODO: replace with actual ECDSA verification in Phase 4
                    stack.push(vec![1]);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_cases() {
        // 2 + 3 == 5 => 2 3 OP_ADD 5 OP_EQUAL
        let script_sig = vec![
            Opcode::OpPushData(vec![0x02]),
        ];

        let script_pubkey = vec![
            Opcode::OpPushData(vec![0x03]),
            Opcode::OpAdd,
            Opcode::OpPushData(vec![0x05]),
            Opcode::OpEqual,
        ];

        let result = UtxoVerifier::verify(&script_sig, &script_pubkey);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn test_p2pkh_mock_success() {
        let mock_sig = vec![0x11, 0x22, 0x33];
        let mock_pubkey = vec![0xAA, 0xBB, 0xCC];
        let mock_pubkey_hash = vec![11, 251, 202, 218, 225, 69, 216, 112, 66,
                                    141, 177, 115, 65, 45, 45, 134, 11, 154, 207, 94];

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

        let result = UtxoVerifier::verify(&script_sig, &script_pubkey);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn test_p2pkh_mock_wrong_hash_fail() {
        let mock_sig = vec![0x11, 0x22, 0x33];
        let mock_pubkey = vec![0xAA, 0xBB, 0xCC];
        let wrong_pubkey_hash = vec![0x99, 0x00, 0x00, 0x00];

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

        let result = UtxoVerifier::verify(&script_sig, &script_pubkey);
        assert_eq!(result, Err(VerificationError::VerifyFailed));
    }
}
