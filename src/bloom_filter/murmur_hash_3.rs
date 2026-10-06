pub fn murmur_hash_3(key: &[u8], seed: u32) -> u32 {
    let c1: u32 = 0xcc9e2d51;
    let c2: u32 = 0x1b873593;
    let r1: u32 = 15;
    let r2: u32 = 13;
    let m: u32 = 5;
    let n: u32 = 0xe6546b64;

    let mut hash: u32 = seed;
    let mut i = 0;

    while i + 4 <= key.len() {
        // let mut k = u32::from_le_bytes([key[i], key[i + 1], key[i + 2], key[i + 3]]);

        // This way is faster than using 'from_le_bytes'
        let mut k = (key[i] as u32)
            | ((key[i + 1] as u32) << 8)
            | ((key[i + 2] as u32) << 16)
            | ((key[i + 3] as u32) << 24);

        k = k.wrapping_mul(c1);
        k = k.rotate_left(r1);
        k = k.wrapping_mul(c2);

        // wrapping_mul means to preserve the last bits and not panic on overflow
        // Example: 0xffffffff * 2 = 0xfffffffe, instead of panic

        // rotate_left means to rotate the bits to the left, and the bits that fall off the left
        // end are reintroduced on the right end
        // Example: 0b00000001.rotate_left(1) = 0b00000010, 0b10000000.rotate_left(1) = 0b00000001

        hash ^= k;
        hash = hash.rotate_left(r2);
        hash = hash.wrapping_mul(m).wrapping_add(n);

        i += 4;
    }

    // Handle remaining bytes
    let mut k: u32 = 0;
    let remaining = key.len() & 3;
    if remaining == 3 {
        k ^= (key[i + 2] as u32) << 16;
    }
    if remaining >= 2 {
        k ^= (key[i + 1] as u32) << 8;
    }
    if remaining >= 1 {
        k ^= key[i] as u32;
        k = k.wrapping_mul(c1);
        k = k.rotate_left(r1);
        k = k.wrapping_mul(c2);
        hash ^= k;
    }

    // Finalization
    hash ^= key.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;

    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_murmur_hash_3() {
        assert_eq!(murmur_hash_3(b"", 0), 0);
        assert_eq!(murmur_hash_3(b"", 1), 1364076727);
        assert_eq!(murmur_hash_3(b"hello", 0), 613153351);
        assert_eq!(murmur_hash_3(b"Hello world!", 0), 1652231212);
        assert_eq!(murmur_hash_3(b"Hello world!", 1), 2261765137);
        assert_eq!(murmur_hash_3(b"Hello world!", 2), 2318682696);
    }

    #[test]
    fn test_performance() {
        let a_long_string = "a".repeat(1000);
        let seed = 42;
        let start = std::time::Instant::now();
        for _ in 0..1_000_000 {
            murmur_hash_3(a_long_string.as_bytes(), seed);
        }
        let duration = start.elapsed();
        println!("Time taken for 1,000,000 iterations: {:?}", duration); // around 2.27s on my machine
    }
}
