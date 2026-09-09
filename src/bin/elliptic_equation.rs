use num_bigint::BigUint;

use bitcoin_insights::{get_uncompressed_pubkey, random_salt};

fn main() {
    // Prime field modulus for secp256k1
    let p = BigUint::parse_bytes(
        b"115792089237316195423570985008687907853269984665640564039457584007908834671663",
        10,
    )
    .unwrap();

    let private_key_bytes = random_salt(32);

    // uncompressed public key (65 bytes: 0x04 + 32 bytes X + 32 bytes Y)
    let uncompressed_pubkey =
        get_uncompressed_pubkey(&private_key_bytes.as_slice().try_into().unwrap());

    // Extract X and Y coordinates (skip first byte 0x04)
    let x_bytes = &uncompressed_pubkey[1..33];
    let y_bytes = &uncompressed_pubkey[33..65];

    let x = BigUint::from_bytes_be(x_bytes);
    let y = BigUint::from_bytes_be(y_bytes);

    println!("\n🔬 Testing Elliptic Curve Equation: y² = x³ + 7 (mod p)");
    println!("📐 Curve: secp256k1");
    println!("🔢 Prime p = {}", p);
    println!("\n📍 Public Key Coordinates:");
    println!("  x = {}", x);
    println!("  y = {}", y);

    // Calculate left side: y² mod p
    let left_side = (&y * &y) % &p;

    // Calculate right side: (x³ + 7) mod p
    let x_cubed = (&x * &x * &x) % &p;
    let right_side = (x_cubed + BigUint::from(7u32)) % &p;

    println!("\n🧮 Calculation:");
    println!("  Left side  (y²)     = {}", left_side);
    println!("  Right side (x³ + 7) = {}", right_side);

    // Verify the equation
    let difference = if left_side >= right_side {
        (&left_side - &right_side) % &p
    } else {
        (&right_side - &left_side) % &p
    };

    println!("\n✅ Verification:");
    println!("  (x³ + 7 - y²) mod p = {}", difference);

    if left_side == right_side {
        println!("  ✅ PASS: The point lies on the elliptic curve!");
    } else {
        println!("  ❌ FAIL: The point does NOT lie on the elliptic curve!");
        panic!("Elliptic curve equation verification failed!");
    }

    assert_eq!(
        left_side, right_side,
        "Point must satisfy the elliptic curve equation"
    );
}
