use std::time::{Duration, SystemTime};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use x25519_dalek::StaticSecret;

use crate::envelope::client::{client_handshake, InMemoryConn, PacketConn};
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

#[test]
fn handshake_tolerates_junk_mismatch() {
    let (mut c1, c2) = InMemoryConn::pair();

    // Server expects 0 junk packets (Jc=0)
    let mut server_cfg = test_framer().config();
    server_cfg.jc = 0;
    let server_framer = Framer::new(server_cfg).unwrap();

    // Client sends 10 junk packets (Jc=10)
    let mut client_cfg = test_framer().config();
    client_cfg.jc = 10;
    let client_framer = Framer::new(client_cfg).unwrap();

    let mut rng = ChaCha20Rng::seed_from_u64(3);

    let handle = std::thread::spawn(move || {
        let mut server = crate::envelope::server::ServerConn::new(
            c2,
            server_framer,
            ReplayCache::new(Duration::from_secs(10), 16),
            SharedRng::from_seed(9),
        );
        let (msg, _) = server.handle_preamble().unwrap();
        assert_eq!(msg, MessageType::Initiation);
        // Server should respond (mock logic)
        server.send_response(MessageType::Response, b"ok").unwrap();
    });

    client_handshake(&mut c1, &client_framer, b"init", &mut rng).unwrap();
    handle.join().unwrap();
}

#[test]
fn handshake_filters_invalid_header() {
    let (mut c1, c2) = InMemoryConn::pair();
    let server_framer = test_framer(); // H1="1-1"

    let mut bad_client_cfg = test_framer().config();
    bad_client_cfg.h1 = "9-9".into(); // Mismatching header
    let bad_client_framer = Framer::new(bad_client_cfg).unwrap();

    let good_client_framer = test_framer();

    let mut rng = ChaCha20Rng::seed_from_u64(3);

    let handle = std::thread::spawn(move || {
        let mut server = crate::envelope::server::ServerConn::new(
            c2,
            server_framer,
            ReplayCache::new(Duration::from_secs(10), 16),
            SharedRng::from_seed(9),
        );

        // This should block ignoring the bad handshake, and only return when the good one arrives
        let (msg, payload) = server.handle_preamble().unwrap();
        assert_eq!(msg, MessageType::Initiation);
        assert_eq!(payload, b"good_init");
        server.send_response(MessageType::Response, b"ok").unwrap();
    });

    // 1. Manually send bad init frame
    let bad_frame = bad_client_framer
        .encode_frame(MessageType::Initiation, b"bad_init")
        .unwrap();
    c1.send(bad_frame).unwrap();

    // 2. Now send valid handshake
    client_handshake(&mut c1, &good_client_framer, b"good_init", &mut rng).unwrap();

    handle.join().unwrap();
}

#[test]
fn handshake_interspersed_noise_tolerance() {
    let (mut c1, c2) = InMemoryConn::pair();
    let framer = test_framer();
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    let handle = std::thread::spawn(move || {
        let mut server = crate::envelope::server::ServerConn::new(
            c2,
            framer,
            ReplayCache::new(Duration::from_secs(10), 16),
            SharedRng::from_seed(9),
        );
        let (msg, payload) = server.handle_preamble().unwrap();
        assert_eq!(msg, MessageType::Initiation);
        assert_eq!(payload, b"finally_good");
        server.send_response(MessageType::Response, b"ok").unwrap();
    });

    // Send a messy sequence of noise
    for _ in 0..5 {
        c1.send(vec![1, 2, 3]).unwrap(); // Junk
    }

    // Send signatures (which server currently ignores as noise)
    let framer_complex = test_framer();
    for sig in framer_complex.signature_datagrams().unwrap() {
        c1.send(sig).unwrap();
    }

    // Interspersed junk
    c1.send(vec![0u8; 100]).unwrap();

    // Finally the good one
    client_handshake(&mut c1, &framer_complex, b"finally_good", &mut rng).unwrap();

    handle.join().unwrap();
}

#[test]
fn handshake_strict_padding_match() {
    let (mut c1, c2) = InMemoryConn::pair();

    // Server expects S1=20
    let mut server_cfg = test_framer().config();
    server_cfg.s1 = 20;
    let server_framer = Framer::new(server_cfg).unwrap();

    // Client sends S1=10
    let mut client_cfg = test_framer().config();
    client_cfg.s1 = 10;
    let client_framer = Framer::new(client_cfg).unwrap();

    let mut rng = ChaCha20Rng::seed_from_u64(3);

    std::thread::spawn(move || {
        let mut server = crate::envelope::server::ServerConn::new(
            c2,
            server_framer,
            ReplayCache::new(Duration::from_secs(10), 16),
            SharedRng::from_seed(9),
        );
        let _ = server.handle_preamble();
    });

    // This should timeout (Err) because server is looking at the wrong offset for the header
    let res = client_handshake(&mut c1, &client_framer, b"init", &mut rng);
    assert!(res.is_err());
}

#[test]
fn handshake_strict_header_match() {
    let (mut c1, c2) = InMemoryConn::pair();

    // Server expects H1="1-1"
    let server_framer = test_framer();

    // Client sends H1="9-9"
    let mut client_cfg = test_framer().config();
    client_cfg.h1 = "9-9".into();
    let client_framer = Framer::new(client_cfg).unwrap();

    let mut rng = ChaCha20Rng::seed_from_u64(3);

    std::thread::spawn(move || {
        let mut server = crate::envelope::server::ServerConn::new(
            c2,
            server_framer,
            ReplayCache::new(Duration::from_secs(10), 16),
            SharedRng::from_seed(9),
        );
        let _ = server.handle_preamble();
    });

    // Should timeout because header validation fails
    let res = client_handshake(&mut c1, &client_framer, b"init", &mut rng);
    assert!(res.is_err());
}
