use hex::FromHex;
use thiserror::Error;

use super::Obf;

#[derive(Debug, Error)]
pub enum BytesObfError {
    #[error("empty argument")]
    Empty,
    #[error("odd amount of symbols")]
    OddSymbols,
    #[error("{0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
pub struct BytesObf {
    data: Vec<u8>,
}

impl BytesObf {
    pub fn new(val: &str) -> Result<Self, BytesObfError> {
        let trimmed = val.trim_start_matches("0x");
        if trimmed.is_empty() {
            return Err(BytesObfError::Empty);
        }
        if !trimmed.len().is_multiple_of(2) {
            return Err(BytesObfError::OddSymbols);
        }
        let data = Vec::from_hex(trimmed).map_err(|e| BytesObfError::Parse(e.to_string()))?;
        Ok(Self { data })
    }
}

impl Obf for BytesObf {
    fn obfuscate(&self, dst: &mut [u8], _src: &[u8]) {
        dst[..self.data.len()].copy_from_slice(&self.data);
    }

    fn deobfuscate(&self, _dst: &mut [u8], src: &[u8]) -> bool {
        src.get(..self.data.len()) == Some(self.data.as_slice())
    }

    fn obfuscated_len(&self, _src_len: usize) -> usize {
        self.data.len()
    }

    fn deobfuscated_len(&self, _src_len: usize) -> usize {
        0
    }
}
