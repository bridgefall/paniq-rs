use std::time::{Duration, SystemTime};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use x25519_dalek::StaticSecret;

use crate::envelope::client::{client_handshake, InMemoryConn};
use crate::envelope::enc_timestamp::{open_timestamp, seal_timestamp};
use crate::envelope::mac1::{compute_mac1, verify_mac1};
use crate::envelope::padding::PaddingPolicy;
use crate::envelope::replay::ReplayCache;
use crate::envelope::transport::{build_transport_payload, decode_transport_payload};
use crate::obf::{Config, Framer, MessageType, SharedRng};

fn test_framer() -> Framer {
    let cfg = Config {
        jc: 1,
        jmin: 4,
        jmax: 4,
        s1: 0,
        s2: 0,
        s3: 0,
        s4: 0,
        h1: "1-1".into(),
        h2: "2-2".into(),
        h3: "3-3".into(),
        h4: "4-4".into(),
        i1: String::new(),
        i2: String::new(),
        i3: String::new(),
        i4: String::new(),
        i5: String::new(),
    };
    let rng = SharedRng::from_seed(42);
    Framer::new_with_rng(cfg, rng).unwrap()
}

#[test]
fn padding_policy_respects_bounds() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let policy = PaddingPolicy {
        enabled: true,
        min: 2,
        max: 4,
        burst_min: 5,
        burst_max: 5,
        burst_prob: 0.0,
    };
    let pad = policy.padding_len(3, 10, &mut rng);
    assert!(pad >= 2 && pad <= 4);
}

#[test]
fn transport_round_trip() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let policy = PaddingPolicy {
        enabled: true,
        min: 0,
        max: 2,
        burst_min: 0,
        burst_max: 0,
        burst_prob: 0.0,
    };
    let payload = b"hello";
    let encoded = build_transport_payload(payload, Some(5), &policy, 64, &mut rng).unwrap();
    let decoded = decode_transport_payload(&encoded, true, Some(|c| c == 5)).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn mac1_computes_and_verifies() {
    let key = b"test-key";
    let data = b"data";
    let mac = compute_mac1(key, data).unwrap();
    verify_mac1(key, data, &mac).unwrap();
}

#[test]
fn replay_cache_blocks_duplicate() {
    let mut cache = ReplayCache::new(Duration::from_secs(5), 10);
    let now = SystemTime::now();
    let key = b"0123456789abcdef";
    cache.check_and_insert(now, b"p", key).unwrap();
    assert!(cache.check_and_insert(now, b"p", key).is_err());
}

#[test]
fn encrypted_timestamp_cycle() {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let client_secret = StaticSecret::from([1u8; 32]);
    let server_secret = StaticSecret::from([2u8; 32]);
    let client_pub = (&client_secret).into();
    let server_pub = (&server_secret).into();
    let now = SystemTime::now();
    let encoded = seal_timestamp(&client_secret, &server_pub, now, &mut rng).unwrap();
    let opened = open_timestamp(&server_secret, &client_pub, &encoded).unwrap();
    assert!(opened.duration_since(now).unwrap() < Duration::from_secs(1));
}

#[test]
fn client_server_handshake_cycle() {
    let (mut c1, c2) = InMemoryConn::pair();
    let framer = test_framer();
    let mut rng = ChaCha20Rng::seed_from_u64(3);

    // server preps to receive
    let framer_clone = test_framer();
    let handle = std::thread::spawn(move || {
        let mut server = crate::envelope::server::ServerConn::new(
            c2,
            framer_clone,
            ReplayCache::new(Duration::from_secs(10), 16),
            SharedRng::from_seed(9),
        );
        let (msg, payload) = server.handle_preamble().unwrap();
        assert_eq!(msg, MessageType::Initiation);
        server
            .send_response(MessageType::Response, &payload)
            .unwrap();
    });

    client_handshake(&mut c1, &framer, b"init", &mut rng).unwrap();
    handle.join().unwrap();
}
