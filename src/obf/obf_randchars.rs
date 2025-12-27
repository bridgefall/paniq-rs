use thiserror::Error;

use super::{Obf, SharedRng};

const CHARS52: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(Debug, Error)]
pub enum RandCharsObfError {
    #[error("{0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
pub struct RandCharsObf {
    length: usize,
    rng: SharedRng,
}

impl RandCharsObf {
    pub fn new(val: &str, rng: SharedRng) -> Result<Self, RandCharsObfError> {
        let length = val
            .parse::<usize>()
            .map_err(|e| RandCharsObfError::Parse(e.to_string()))?;
        Ok(Self { length, rng })
    }
}

impl Obf for RandCharsObf {
    fn obfuscate(&self, dst: &mut [u8], _src: &[u8]) {
        self.rng.fill_bytes(&mut dst[..self.length]);
        for b in &mut dst[..self.length] {
            *b = CHARS52[(*b as usize) % CHARS52.len()];
        }
    }

    fn deobfuscate(&self, _dst: &mut [u8], src: &[u8]) -> bool {
        src.iter()
            .take(self.length)
            .all(|b| (*b >= b'a' && *b <= b'z') || (*b >= b'A' && *b <= b'Z'))
    }

    fn obfuscated_len(&self, _src_len: usize) -> usize {
        self.length
    }

    fn deobfuscated_len(&self, _src_len: usize) -> usize {
        0
    }
}
