use bitcoin_insights::bloom_filter::BloomFilter;

fn main() {
    let mut bloom_filter = BloomFilter::new(64, 3);

    // Insert some items into the Bloom filter
    bloom_filter.insert(b"apple");
    bloom_filter.insert(b"banana");
    bloom_filter.insert(b"orange");

    // Check for membership
    println!("Is 'apple' in the Bloom filter? {}", bloom_filter.contains(b"apple"));
    println!("Is 'grape' in the Bloom filter? {}", bloom_filter.contains(b"grape"));

    println!("False positive probability: {:.4}%", bloom_filter.false_positive_probability(3) * 100.0);

    println!("Bloom filter bits:");
    bloom_filter.print_bits();
}