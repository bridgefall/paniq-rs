use super::Obf;

#[derive(Debug, Default, Clone)]
pub struct DataObf;

impl Obf for DataObf {
    fn obfuscate(&self, dst: &mut [u8], src: &[u8]) {
        dst[..src.len()].copy_from_slice(src);
    }

    fn deobfuscate(&self, dst: &mut [u8], src: &[u8]) -> bool {
        dst[..src.len()].copy_from_slice(src);
        true
    }

    fn obfuscated_len(&self, n: usize) -> usize {
        n
    }

    fn deobfuscated_len(&self, n: usize) -> usize {
        n
    }
}
