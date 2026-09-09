mod address;
mod crypto;
mod hex;
mod k256;

// Official feature modules
pub mod bip32;
pub mod bip39;
pub mod utxo_verifier;

// Re-export modules for easier access
pub use address::*;
pub use crypto::*;
pub use hex::*;
pub use k256::*;
