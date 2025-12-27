#![no_main]
use libfuzzer_sys::fuzz_target;
use paniq::envelope::transport::{decode_transport_payload, build_transport_payload};
use paniq::envelope::padding::PaddingPolicy;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;

fuzz_target!(|data: &[u8]| {
    // Decode should not panic on any input - expect_counter=false, no validator
    let _ = decode_transport_payload(data, false, None::<fn(u64) -> bool>);

    // Test encoding with fuzz data as payload
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let policy = PaddingPolicy {
        enabled: true,
        min: 0,
        max: 64,
        burst_min: 0,
        burst_max: 0,
        burst_prob: 0.0,
    };

    let _ = build_transport_payload(data, Some(1), &policy, 1024, &mut rng);
});
