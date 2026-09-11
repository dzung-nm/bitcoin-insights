use bitcoin_insights::script::*;

fn main() {
    let script = vec![
        Opcode::OpDup,
        Opcode::OpHash160,
        Opcode::OpPushData(vec![0x01, 0x02, 0x03]),
        Opcode::OpEqualVerify,
        Opcode::OpCheckSig,
    ];

    let script = Script::new(script);
    println!("\nScript: {}", script.to_hex());
    println!("P2SH Address: {}", script.to_p2sh_address());
}