#![no_main]
use libfuzzer_sys::fuzz_target;

// Main fuzz target that exercises all components
fuzz_target!(|data: &[u8]| {
    // 1. Chain parser - try to parse as UTF-8
    if let Ok(spec) = std::str::from_utf8(data) {
        let _ = paniq::obf::parse_chain(spec);
    }

    // 2. Frame decoder
    let cfg = paniq::obf::Config {
        jc: 0, jmin: 0, jmax: 0,
        s1: 0, s2: 0, s3: 0, s4: 0,
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
    let rng = paniq::obf::SharedRng::from_seed(12345);
    if let Ok(framer) = paniq::obf::Framer::new_with_rng(cfg, rng) {
        let _ = framer.decode_frame(data);
        let _ = framer.encode_frame(paniq::obf::MessageType::Initiation, data);
    }

    // 3. Payload decoder - expect_counter=false, no validator
    let _ = paniq::envelope::transport::decode_transport_payload(
        data, false, None::<fn(u64) -> bool>
    );

    // 4. Replay cache
    let mut cache = paniq::envelope::replay::ReplayCache::new(std::time::Duration::from_secs(5), 100);
    let mut mac1 = [0u8; 16];
    let len = data.len().min(16);
    mac1[..len].copy_from_slice(&data[..len]);
    let payload = if data.len() > 16 { &data[16..] } else { &[] };
    let timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    let _ = cache.check_and_insert(timestamp, payload, &mac1);
});
