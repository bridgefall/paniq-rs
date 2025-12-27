use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::sync::{Arc, Mutex};

mod chain;
mod config;
mod framer;
mod header;
mod headers;
mod obf_bytes;
mod obf_data;
mod obf_datasize;
mod obf_datastring;
mod obf_rand;
mod obf_randchars;
mod obf_randdigits;
mod obf_timestamp;
#[cfg(test)]
mod tests;

pub use chain::{
    parse_chain, parse_chain_with_rng, parse_chains, parse_chains_with_rng, Chain, ChainError,
    ChainSet, ChainSetError,
};
pub use config::{Config, ConfigError};
pub use framer::{Framer, MessageType};
pub use header::{parse_header, parse_header_with_rng, MagicHeader};
pub use headers::{
    default_header_specs, parse_headers, parse_headers_with_defaults,
    parse_headers_with_defaults_and_rng, parse_headers_with_rng, HeaderSet, HeaderSetError,
};
pub use obf_bytes::BytesObf;
pub use obf_data::DataObf;
pub use obf_datasize::DataSizeObf;
pub use obf_datastring::DataStringObf;
pub use obf_rand::RandObf;
pub use obf_randchars::RandCharsObf;
pub use obf_randdigits::RandDigitsObf;
pub use obf_timestamp::TimestampObf;

/// Trait implemented by all obfuscation units.
pub trait Obf: Send + Sync {
    fn obfuscate(&self, dst: &mut [u8], src: &[u8]);
    fn deobfuscate(&self, dst: &mut [u8], src: &[u8]) -> bool;
    fn obfuscated_len(&self, src_len: usize) -> usize;
    fn deobfuscated_len(&self, src_len: usize) -> usize;
}

/// Shared RNG wrapper used to support deterministic tests.
#[derive(Clone, Debug)]
pub struct SharedRng(pub Arc<Mutex<StdRng>>);

impl SharedRng {
    pub fn from_seed(seed: u64) -> Self {
        Self(Arc::new(Mutex::new(StdRng::seed_from_u64(seed))))
    }

    pub fn from_entropy() -> Self {
        Self(Arc::new(Mutex::new(StdRng::from_entropy())))
    }

    pub fn fill_bytes(&self, buf: &mut [u8]) {
        if let Ok(mut rng) = self.0.lock() {
            rng.fill_bytes(buf);
        }
    }
}

impl Default for SharedRng {
    fn default() -> Self {
        Self::from_entropy()
    }
}
