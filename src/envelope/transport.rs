use rand::RngCore;

use crate::envelope::padding::PaddingPolicy;
use crate::envelope::EnvelopeError;
use crate::telemetry;

const COUNTER_SIZE: usize = 8;
const LEN_SIZE: usize = 2;

pub fn build_transport_payload<R: RngCore>(
    payload: &[u8],
    counter: Option<u64>,
    padding: &PaddingPolicy,
    max_payload: usize,
    rng: &mut R,
) -> Result<Vec<u8>, EnvelopeError> {
    if payload.len() > u16::MAX as usize {
        telemetry::record_transport_payload_too_large();
        return Err(EnvelopeError::PayloadTooLarge);
    }
    let pad_len = padding.padding_len(payload.len(), max_payload, rng);
    if payload.len() + pad_len + LEN_SIZE + counter.map(|_| COUNTER_SIZE).unwrap_or(0) > max_payload
    {
        telemetry::record_transport_payload_too_large();
        return Err(EnvelopeError::PayloadTooLarge);
    }
    let mut out = Vec::with_capacity(COUNTER_SIZE + LEN_SIZE + payload.len() + pad_len);
    if let Some(counter) = counter {
        out.extend_from_slice(&counter.to_be_bytes());
    }
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    if pad_len > 0 {
        let mut pad_buf = vec![0u8; pad_len];
        rng.fill_bytes(&mut pad_buf);
        out.extend_from_slice(&pad_buf);
    }
    telemetry::record_transport_out(payload.len(), pad_len, out.len());
    Ok(out)
}

pub fn decode_transport_payload<F>(
    data: &[u8],
    expect_counter: bool,
    mut counter_validator: Option<F>,
) -> Result<Vec<u8>, EnvelopeError>
where
    F: FnMut(u64) -> bool,
{
    let mut offset = 0;
    if expect_counter {
        if data.len() < COUNTER_SIZE {
            telemetry::record_transport_invalid_length();
            return Err(EnvelopeError::InvalidLength);
        }
        let mut ctr_bytes = [0u8; COUNTER_SIZE];
        ctr_bytes.copy_from_slice(&data[..COUNTER_SIZE]);
        offset += COUNTER_SIZE;
        let counter = u64::from_be_bytes(ctr_bytes);
        if let Some(validator) = counter_validator.as_mut() {
            if !validator(counter) {
                telemetry::record_transport_counter_reject();
                return Err(EnvelopeError::CounterRejected);
            }
        }
    }
    if data.len() < offset + LEN_SIZE {
        telemetry::record_transport_invalid_length();
        return Err(EnvelopeError::InvalidLength);
    }
    let mut len_bytes = [0u8; LEN_SIZE];
    len_bytes.copy_from_slice(&data[offset..offset + LEN_SIZE]);
    offset += LEN_SIZE;
    let len = u16::from_be_bytes(len_bytes) as usize;
    if data.len() < offset + len {
        telemetry::record_transport_invalid_length();
        return Err(EnvelopeError::InvalidLength);
    }
    let pad_len = data.len().saturating_sub(offset + len);
    telemetry::record_transport_in(len, pad_len, data.len());
    Ok(data[offset..offset + len].to_vec())
}
