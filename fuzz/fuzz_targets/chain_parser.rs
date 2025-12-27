#![no_main]
use libfuzzer_sys::fuzz_target;
use paniq::obf::parse_chain;

fuzz_target!(|data: &[u8]| {
    // Try to parse as UTF-8 string, skip if invalid
    let spec = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Parsing should not panic on any input
    let _ = parse_chain(spec);
});
