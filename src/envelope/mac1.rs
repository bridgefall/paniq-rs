use blake2::digest::Mac;
use blake2::Blake2sMac256;
use subtle::ConstantTimeEq;

use crate::envelope::EnvelopeError;

pub const MAC1_LEN: usize = 16;

pub fn compute_mac1(key: &[u8], data: &[u8]) -> Result<[u8; MAC1_LEN], EnvelopeError> {
    let mut mac =
        Blake2sMac256::new_from_slice(key).map_err(|e| EnvelopeError::Timestamp(e.to_string()))?;
    mac.update(data);
    let mut out = [0u8; MAC1_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes()[..MAC1_LEN]);
    Ok(out)
}

pub fn verify_mac1(key: &[u8], data: &[u8], expected: &[u8]) -> Result<(), EnvelopeError> {
    if expected.len() != MAC1_LEN {
        return Err(EnvelopeError::Authentication);
    }
    let calc = compute_mac1(key, data)?;
    if calc.ct_eq(expected).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(EnvelopeError::Authentication)
    }
}
