pub const OP_ADD: u8 = 0x93;
pub const OP_DUP: u8 = 0x76;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUAL_VERIFY: u8 = 0x88;
pub const OP_CHECKSIG: u8 = 0xac;

#[derive(Debug, Clone, PartialEq)]
pub enum Opcode {
    OpPushData(Vec<u8>),
    OpAdd,
    OpDup,
    OpHash160,
    OpEqual,
    OpEqualVerify,
    OpCheckSig,
}
