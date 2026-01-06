#![cfg(feature = "kcp")]

use std::collections::{BTreeMap, HashSet};

use paniq::envelope::transport::{build_transport_payload, transport_overhead};
use paniq::obf::{Framer, MessageType, SharedRng};
use paniq::profile::Profile;
use rand::rngs::StdRng;
use rand::SeedableRng;

const SAMPLE_COUNT: usize = 64;
const PADDING_RNG_SEED: u64 = 0x5EED_5EED;
const FRAMER_RNG_SEED: u64 = 0xC0FF_EE00;

#[test]
fn transport_padding_produces_size_variance() {
    let profile = Profile::from_file("examples/profile.json").unwrap();
    let padding = profile.transport_padding_policy();
    assert!(
        padding.enabled,
        "transport padding must be enabled in examples/profile.json"
    );

    let max_payload = profile.effective_kcp_max_payload();
    let overhead = transport_overhead(profile.obfuscation.transport_replay);
    let max_pad = padding.max_padding();
    assert!(
        max_payload > overhead + max_pad,
        "max_payload must leave headroom for padding"
    );

    let payload_len = (max_payload - overhead - max_pad) / 2;
    assert!(payload_len > 0, "payload length must be non-zero");
    let payload = vec![0u8; payload_len];

    let framer_rng = SharedRng::from_seed(FRAMER_RNG_SEED);
    let framer = Framer::new_with_rng(profile.obf_config(), framer_rng).unwrap();
    let mut padding_rng = StdRng::seed_from_u64(PADDING_RNG_SEED);

    let mut sizes = HashSet::new();
    let mut distribution: BTreeMap<usize, usize> = BTreeMap::new();
    let mut saw_padding = false;

    for _ in 0..SAMPLE_COUNT {
        let transport = build_transport_payload(
            &payload,
            None,
            &padding,
            max_payload,
            &mut padding_rng,
        )
        .unwrap();

        let pad_len = transport
            .len()
            .saturating_sub(overhead + payload_len);
        if pad_len > 0 {
            saw_padding = true;
        }

        let datagram = framer
            .encode_frame(MessageType::Transport, &transport)
            .unwrap();
        let size = datagram.len();
        sizes.insert(size);
        *distribution.entry(size).or_default() += 1;
    }

    println!("transport padding size distribution (count={}):", SAMPLE_COUNT);
    for (size, count) in &distribution {
        let pct = (*count as f64 / SAMPLE_COUNT as f64) * 100.0;
        println!("  size={} count={} pct={:.2}", size, count, pct);
    }

    assert!(saw_padding, "expected padding bytes to be applied");
    assert!(sizes.len() > 1, "expected packet size variance");
}
