#![no_main]
use libfuzzer_sys::fuzz_target;
use paniq::envelope::replay::ReplayCache;
use std::time::{Duration, UNIX_EPOCH};

fuzz_target!(|data: &[u8]| {
    // Create a replay cache with a short window
    let mut cache = ReplayCache::new(Duration::from_secs(5), 100);

    // Use the fuzz data to create a MAC1 (need exactly 16 bytes)
    let mut mac1 = [0u8; 16];
    if data.len() >= 16 {
        mac1.copy_from_slice(&data[..16]);
    } else {
        mac1[..data.len()].copy_from_slice(data);
    }

    // Use remaining data as payload
    let payload = if data.len() > 16 {
        &data[16..]
    } else {
        &[]
    };

    // Check and insert should not panic on any input
    let timestamp = UNIX_EPOCH + Duration::from_secs(1_000_000);
    let _ = cache.check_and_insert(timestamp, payload, &mac1);

    // Also test with various timestamps derived from data
    if data.len() >= 8 {
        let secs = u64::from_be_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        let timestamp = UNIX_EPOCH + Duration::from_secs(secs % 1_000_000);
        let _ = cache.check_and_insert(timestamp, payload, &mac1);
    }
});
