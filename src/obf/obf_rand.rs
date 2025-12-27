use thiserror::Error;

use super::{Obf, SharedRng};

#[derive(Debug, Error)]
pub enum RandObfError {
    #[error("{0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
pub struct RandObf {
    length: usize,
    rng: SharedRng,
}

impl RandObf {
    pub fn new(val: &str, rng: SharedRng) -> Result<Self, RandObfError> {
        let length = val
            .parse::<usize>()
            .map_err(|e| RandObfError::Parse(e.to_string()))?;
        Ok(Self { length, rng })
    }
}

impl Obf for RandObf {
    fn obfuscate(&self, dst: &mut [u8], _src: &[u8]) {
        self.rng.fill_bytes(&mut dst[..self.length]);
    }

    fn deobfuscate(&self, _dst: &mut [u8], _src: &[u8]) -> bool {
        true
    }

    fn obfuscated_len(&self, _src_len: usize) -> usize {
        self.length
    }

    fn deobfuscated_len(&self, _src_len: usize) -> usize {
        0
    }
}
