use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

use blake2::digest::Mac;
use blake2::Blake2sMac256;

use crate::envelope::EnvelopeError;

#[derive(Debug)]
pub struct ReplayCache {
    window: Duration,
    max_entries: usize,
    entries: HashMap<[u8; 16], SystemTime>,
    order: VecDeque<[u8; 16]>,
}

impl ReplayCache {
    pub fn new(window: Duration, max_entries: usize) -> Self {
        Self {
            window,
            max_entries,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn check_and_insert(
        &mut self,
        timestamp: SystemTime,
        payload: &[u8],
        mac1: &[u8],
    ) -> Result<(), EnvelopeError> {
        self.evict(timestamp);
        let mut mac = Blake2sMac256::new_from_slice(mac1)
            .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?;
        mac.update(
            &timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_be_bytes(),
        );
        mac.update(payload);
        let digest = mac.finalize().into_bytes();
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        if self.entries.contains_key(&key) {
            return Err(EnvelopeError::Replay);
        }
        self.entries.insert(key, timestamp);
        self.order.push_back(key);
        if self.order.len() > self.max_entries {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        Ok(())
    }

    fn evict(&mut self, now: SystemTime) {
        while let Some(front) = self.order.front().cloned() {
            if let Some(ts) = self.entries.get(&front) {
                if let Ok(elapsed) = now.duration_since(*ts) {
                    if elapsed <= self.window {
                        break;
                    }
                } else {
                    self.entries.clear();
                    self.order.clear();
                    break;
                }
                self.order.pop_front();
                self.entries.remove(&front);
            } else {
                self.order.pop_front();
            }
        }
    }
}
