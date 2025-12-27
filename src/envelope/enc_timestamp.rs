use std::time::{SystemTime, UNIX_EPOCH};

use blake2::Digest;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::envelope::EnvelopeError;

#[derive(Debug, Clone)]
pub struct EncodedTimestamp {
    pub ephemeral_pub: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

fn serialize_timestamp(ts: SystemTime) -> [u8; 12] {
    let since = ts.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = (since.as_secs() + 0x4000_0000_0000_0000) as u64; // TAI64 offset approximation
    let nanos = since.subsec_nanos();
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&seconds.to_be_bytes());
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    out
}

fn derive_key(secret: &StaticSecret, peer: &PublicKey) -> Key {
    let shared = secret.diffie_hellman(peer);
    let mut hasher = blake2::Blake2s256::new();
    use blake2::digest::Update;
    Update::update(&mut hasher, shared.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    Key::from_slice(&key).to_owned()
}

pub fn seal_timestamp<R: RngCore>(
    secret: &StaticSecret,
    peer: &PublicKey,
    now: SystemTime,
    rng: &mut R,
) -> Result<EncodedTimestamp, EnvelopeError> {
    let key = derive_key(secret, peer);
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let plaintext = serialize_timestamp(now);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?;
    Ok(EncodedTimestamp {
        ephemeral_pub: PublicKey::from(secret).to_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn open_timestamp(
    secret: &StaticSecret,
    peer: &PublicKey,
    encoded: &EncodedTimestamp,
) -> Result<SystemTime, EnvelopeError> {
    let key = derive_key(secret, peer);
    let cipher = ChaCha20Poly1305::new(&key);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encoded.nonce),
            encoded.ciphertext.as_ref(),
        )
        .map_err(|_| EnvelopeError::Authentication)?;
    if plaintext.len() != 12 {
        return Err(EnvelopeError::Timestamp("invalid length".into()));
    }
    let mut secs_bytes = [0u8; 8];
    let mut nanos_bytes = [0u8; 4];
    secs_bytes.copy_from_slice(&plaintext[..8]);
    nanos_bytes.copy_from_slice(&plaintext[8..]);
    let secs = u64::from_be_bytes(secs_bytes).saturating_sub(0x4000_0000_0000_0000);
    let nanos = u32::from_be_bytes(nanos_bytes);
    Ok(UNIX_EPOCH + std::time::Duration::new(secs, nanos))
}
