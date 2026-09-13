use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::script::opcode::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Script {
    pub opcodes: Vec<Opcode>,
}

impl Script {
    pub fn new(opcodes: Vec<Opcode>) -> Self {
        Script { opcodes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for opcode in &self.opcodes {
            match opcode {
                Opcode::OpPushData(data) => {
                    bytes.push(data.len() as u8);
                    bytes.extend_from_slice(data);
                }
                Opcode::OpAdd => bytes.push(OP_ADD),
                Opcode::OpDup => bytes.push(OP_DUP),
                Opcode::OpHash160 => bytes.push(OP_HASH160),
                Opcode::OpEqual => bytes.push(OP_EQUAL),
                Opcode::OpEqualVerify => bytes.push(OP_EQUAL_VERIFY),
                Opcode::OpCheckSig => bytes.push(OP_CHECKSIG),
                Opcode::OpN(n) => bytes.push(OP_1 + n - 1),
                Opcode::OpCheckMultiSig => bytes.push(OP_CHECKMULTISIG),
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut opcodes = Vec::new();
        let mut i = 0;

        while i < bytes.len() {
            let byte = bytes[i];
            match byte {
                OP_0 => opcodes.push(Opcode::OpPushData(vec![])),
                OP_DUP => opcodes.push(Opcode::OpDup),
                OP_HASH160 => opcodes.push(Opcode::OpHash160),
                OP_EQUAL => opcodes.push(Opcode::OpEqual),
                OP_EQUAL_VERIFY => opcodes.push(Opcode::OpEqualVerify),
                OP_CHECKSIG => opcodes.push(Opcode::OpCheckSig),
                OP_CHECKMULTISIG => opcodes.push(Opcode::OpCheckMultiSig),
                OP_ADD => opcodes.push(Opcode::OpAdd),
                n if n >= OP_1 && n <= OP_16 => opcodes.push(Opcode::OpN(n - OP_1 + 1)),
                n if n >= 0x01 && n <= 0x4b => {
                    let data_len = n as usize;
                    if i + 1 + data_len > bytes.len() {
                        return Err("Invalid script: not enough bytes for Pushdata".to_string());
                    }
                    opcodes.push(Opcode::OpPushData(bytes[i + 1..i + 1 + data_len].to_vec()));
                    i += data_len;
                }
                _ => return Err(format!("Invalid opcode: {}", byte)),
            }
            i += 1;
        }

        Ok(Script { opcodes })
    }

    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn to_p2sh_address(&self) -> String {
        let script_bytes = self.to_bytes();
        let sha256_hash = Sha256::digest(&script_bytes);
        let ripemd160_hash = Ripemd160::digest(&sha256_hash);

        let mut payload = vec![0x05]; // P2SH prefix for mainnet
        payload.extend_from_slice(&ripemd160_hash);

        bs58::encode(payload).with_check().into_string()
    }
    
    /// This is only meaningful if Self is a redeem script. 
    pub fn generate_p2sh_script(&self) -> Script {
        let bytes = self.to_bytes();
        let sha256_hash = Sha256::digest(&bytes);
        let pubkey_hash = Ripemd160::digest(&sha256_hash);
        Script::new(vec![
            Opcode::OpHash160,
            Opcode::OpPushData(pubkey_hash.to_vec()),
            Opcode::OpEqual,
        ])
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_to_bytes_and_from_bytes() {
        let script = Script::new(vec![
            Opcode::OpDup,
            Opcode::OpHash160,
            Opcode::OpPushData(vec![0x01, 0x02, 0x03]),
            Opcode::OpEqualVerify,
            Opcode::OpCheckSig,
        ]);
        let bytes = script.to_bytes();
        let parsed_script = Script::from_bytes(&bytes).unwrap();
        assert_eq!(script.opcodes, parsed_script.opcodes);
    }

    #[test]
    fn test_script_to_hex() {
        let script = Script::new(vec![
            Opcode::OpDup,
            Opcode::OpHash160,
            Opcode::OpPushData(vec![0x01, 0x02, 0x03]),
            Opcode::OpEqualVerify,
            Opcode::OpCheckSig,
        ]);
        let hex = script.to_hex();
        assert_eq!(hex, "76a90301020388ac");
    }

    #[test]
    fn test_script_to_p2sh_address() {
        let script = Script::new(vec![
            Opcode::OpDup,
            Opcode::OpHash160,
            Opcode::OpPushData(vec![0x01, 0x02, 0x03]),
            Opcode::OpEqualVerify,
            Opcode::OpCheckSig,
        ]);
        let address = script.to_p2sh_address();
        assert_eq!(address, "34sXEvxBUirgjpyPDyg7QxjPnsBsUgy3jC");
    }

    #[test]
    fn test_script_from_bytes_invalid() {
        let invalid_bytes = vec![0xff, 0x00, 0x01]; // Invalid opcode 0xff
        let result = Script::from_bytes(&invalid_bytes);
        assert!(result.is_err());

        let invalid_bytes = vec![118, 169, 13, 1, 2, 136, 172];
        let result = Script::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }
}
