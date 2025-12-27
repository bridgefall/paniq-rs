use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

use super::Obf;

#[derive(Debug, Default, Clone)]
pub struct DataStringObf;

impl Obf for DataStringObf {
    fn obfuscate(&self, dst: &mut [u8], src: &[u8]) {
        STANDARD_NO_PAD
            .encode_slice(src, dst)
            .expect("dst length to be sufficient");
    }

    fn deobfuscate(&self, dst: &mut [u8], src: &[u8]) -> bool {
        STANDARD_NO_PAD.decode_slice(src, dst).is_ok()
    }

    fn obfuscated_len(&self, n: usize) -> usize {
        let full_chunks = n / 3;
        let rem = n % 3;
        full_chunks * 4
            + match rem {
                0 => 0,
                1 => 2,
                2 => 3,
                _ => 0,
            }
    }

    fn deobfuscated_len(&self, n: usize) -> usize {
        let full_quads = n / 4;
        let rem = n % 4;
        full_quads * 3
            + match rem {
                0 => 0,
                2 => 1,
                3 => 2,
                _ => 0,
            }
    }
}
