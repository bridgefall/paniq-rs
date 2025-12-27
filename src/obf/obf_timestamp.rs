use std::time::{SystemTime, UNIX_EPOCH};

use super::Obf;

#[derive(Debug, Clone, Default)]
pub struct TimestampObf;

impl Obf for TimestampObf {
    fn obfuscate(&self, dst: &mut [u8], _src: &[u8]) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        dst[..4].copy_from_slice(&now.to_be_bytes());
    }

    fn deobfuscate(&self, _dst: &mut [u8], _src: &[u8]) -> bool {
        true
    }

    fn obfuscated_len(&self, _src_len: usize) -> usize {
        4
    }

    fn deobfuscated_len(&self, _src_len: usize) -> usize {
        0
    }
}
