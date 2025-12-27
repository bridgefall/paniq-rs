use thiserror::Error;

use super::Obf;

#[derive(Debug, Error)]
pub enum DataSizeObfError {
    #[error("{0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
pub struct DataSizeObf {
    length: usize,
}

impl DataSizeObf {
    pub fn new(val: &str) -> Result<Self, DataSizeObfError> {
        let length = val
            .parse::<usize>()
            .map_err(|e| DataSizeObfError::Parse(e.to_string()))?;
        Ok(Self { length })
    }
}

impl Obf for DataSizeObf {
    fn obfuscate(&self, dst: &mut [u8], src: &[u8]) {
        let mut len = src.len();
        for i in (0..self.length).rev() {
            dst[i] = (len & 0xFF) as u8;
            len >>= 8;
        }
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
