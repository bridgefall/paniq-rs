use thiserror::Error;

use super::{Obf, SharedRng};

#[derive(Debug, Error)]
pub enum RandDigitsObfError {
    #[error("{0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
pub struct RandDigitsObf {
    length: usize,
    rng: SharedRng,
}

impl RandDigitsObf {
    pub fn new(val: &str, rng: SharedRng) -> Result<Self, RandDigitsObfError> {
        let length = val
            .parse::<usize>()
            .map_err(|e| RandDigitsObfError::Parse(e.to_string()))?;
        Ok(Self { length, rng })
    }
}

impl Obf for RandDigitsObf {
    fn obfuscate(&self, dst: &mut [u8], _src: &[u8]) {
        self.rng.fill_bytes(&mut dst[..self.length]);
        for b in &mut dst[..self.length] {
            *b = b'0' + (*b % 10);
        }
    }

    fn deobfuscate(&self, _dst: &mut [u8], src: &[u8]) -> bool {
        src.iter()
            .take(self.length)
            .all(|b| *b >= b'0' && *b <= b'9')
    }

    fn obfuscated_len(&self, _src_len: usize) -> usize {
        self.length
    }

    fn deobfuscated_len(&self, _src_len: usize) -> usize {
        0
    }
}
