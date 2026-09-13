pub const OP_0: u8 = 0x00;
pub const OP_ADD: u8 = 0x93;
pub const OP_DUP: u8 = 0x76;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUAL_VERIFY: u8 = 0x88;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKMULTISIG: u8 = 0xae;

/// OP_1 (0x51) through OP_16 (0x60): push the number n onto the stack.
pub const OP_1: u8 = 0x51;
pub const OP_16: u8 = 0x60;

#[derive(Debug, Clone, PartialEq)]
pub enum Opcode {
    OpPushData(Vec<u8>),
    OpAdd,
    OpDup,
    OpHash160,
    OpEqual,
    OpEqualVerify,
    OpCheckSig,
    OpN(u8),
    OpCheckMultiSig,
}
