use crate::bloom_filter::murmur_hash_3::murmur_hash_3;

pub struct BloomFilter {
    bits: Vec<u8>,
    num_bits: usize,
    num_hashes: usize,
}

impl BloomFilter {
    pub fn new(num_bits: usize, num_hashes: usize) -> Self {
        assert!(num_bits > 0);
        assert!(num_hashes > 0);

        BloomFilter {
            bits: vec![0; (num_bits + 7) / 8],
            num_bits,
            num_hashes,
        }
    }

    fn set_bit(&mut self, index: usize) {
        let byte_index = index / 8;
        let bit_index = index % 8;

        self.bits[byte_index] |= 1 << bit_index;
    }

    fn get_bit(&self, index: usize) -> bool {
        let byte_index = index / 8;
        let bit_index = index % 8;

        (self.bits[byte_index] & (1 << bit_index)) != 0
    }

    fn get_indices(&self, key: &[u8]) -> Vec<usize> {
        let h1 = murmur_hash_3(key, 0);
        let h2 = murmur_hash_3(key, 1);

        let mut indices = Vec::with_capacity(self.num_hashes);

        for i in 0..self.num_hashes {
            // Double hashing: h(i) = h1 + i * h2
            let hash = h1.wrapping_add(
                (i as u32).wrapping_mul(h2)
            );
            let index = (hash as usize) % self.num_bits;
            indices.push(index);
        }

        indices
    }

    pub fn insert(&mut self, key: &[u8]) {
        for index in self.get_indices(key) {
            self.set_bit(index);
        }
    }

    pub fn contains(&self, key: &[u8]) -> bool {
        for index in self.get_indices(key) {
            if !self.get_bit(index) {
                return false;
            }
        }
        true
    }

    pub fn false_positive_probability(&self, num_elements: usize) -> f64 {
        let n = num_elements as f64;
        let m = self.num_bits as f64;
        let k = self.num_hashes as f64;

        (1.0 - (-k * n / m).exp()).powf(k)
    }

    pub fn print_bits(&self) {
        for i in 0..self.num_bits {
            let bit = if self.get_bit(i) { '1' } else { '0' };
            print!("{}", bit);
            if (i + 1) % 8 == 0 {
                print!(" ");
            }
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use super::*;

    #[test]
    fn test_correctness() {
        let mut bloom = BloomFilter::new(1000, 5);
        let key1 = b"hello";
        let key2 = b"world";
        bloom.insert(key1);
        bloom.insert(key2);
        assert!(bloom.contains(key1));
        assert!(bloom.contains(key2));
        assert!(!bloom.contains(b"not_inserted"));
    }

    #[test]
    fn test_performance() {
        let mut bloom = BloomFilter::new(10_000_000, 10);

        let start = Instant::now();
        for i in 0..100_000 {
            let key = format!("key{}", i);
            bloom.insert(key.as_bytes());
        }
        let duration = start.elapsed();
        println!("Inserted 100,000 keys in {:?}", duration);

        let start = Instant::now();
        for i in 0..100_000 {
            let key = format!("key{}", i);
            assert!(bloom.contains(key.as_bytes()));
        }
        let duration = start.elapsed();
        println!("Checked 100,000 keys in {:?}", duration);
    }
}

