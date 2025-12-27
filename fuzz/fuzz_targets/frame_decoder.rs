#![no_main]
use libfuzzer_sys::fuzz_target;
use paniq::obf::{Config, Framer, MessageType, SharedRng};

fuzz_target!(|data: &[u8]| {
    // Create a minimal valid config for fuzzing
    let cfg = Config {
        jc: 0,
        jmin: 0,
        jmax: 0,
        s1: 0,
        s2: 0,
        s3: 0,
        s4: 0,
        h1: "100-100".into(),
        h2: "200-200".into(),
        h3: "300-300".into(),
        h4: "400-400".into(),
        i1: "<d>".into(),
        i2: String::new(),
        i3: String::new(),
        i4: String::new(),
        i5: String::new(),
    };

    let rng = SharedRng::from_seed(12345);
    let framer = match Framer::new_with_rng(cfg, rng) {
        Ok(f) => f,
        Err(_) => return,
    };

    // Decode should not panic on any input
    let _ = framer.decode_frame(data);

    // Also test encoding with fuzz data as payload
    let _ = framer.encode_frame(MessageType::Initiation, data);
});
