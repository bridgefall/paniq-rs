use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use hex::decode as hex_decode;
use hex::encode as hex_encode;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use x25519_dalek::StaticSecret;

use paniq::envelope::enc_timestamp::{open_timestamp, seal_timestamp};
use paniq::envelope::mac1::{compute_mac1, verify_mac1};
use paniq::envelope::padding::PaddingPolicy;
use paniq::envelope::transport::{decode_transport_payload, build_transport_payload};
use paniq::envelope::replay::ReplayCache;
use paniq::obf::{parse_chain_with_rng, Config, Framer, MessageType, SharedRng};

#[derive(Deserialize)]
struct ChainVector {
    spec: String,
    input_hex: String,
    output_hex: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct FrameVector {
    msg_type: u8,
    header: String,
    padding: usize,
    payload_hex: String,
    output_hex: String,
}

#[derive(Deserialize)]
struct TransportVector {
    counter: Option<u64>,
    padding: usize,
    payload_hex: String,
    output_hex: String,
}

#[derive(Deserialize)]
struct Mac1Vector {
    key_hex: String,
    input_hex: String,
    output_hex: String,
}

#[derive(Deserialize)]
struct EncTimestampVector {
    client_secret_hex: String,
    server_secret_hex: String,
    timestamp: u64,
    nonce_hex: String,
    ciphertext_hex: String,
    ephemeral_hex: String,
}

#[derive(Deserialize)]
struct ReplayEventVector {
    timestamp: u64,
    payload_hex: String,
    mac1_hex: String,
    accepted: bool,
}

#[derive(Deserialize)]
struct ReplayVector {
    window_secs: u64,
    max_entries: usize,
    events: Vec<ReplayEventVector>,
}

#[derive(Deserialize)]
struct Vectors {
    seed: u64,
    chains: Vec<ChainVector>,
    frames: Vec<FrameVector>,
    transport: Vec<TransportVector>,
    mac1: Vec<Mac1Vector>,
    enc_timestamp: Vec<EncTimestampVector>,
    replay: Vec<ReplayVector>,
}

fn load_vectors() -> Vectors {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("obf-parity/vectors.json");
    let data = fs::read_to_string(path).expect("vectors file");
    serde_json::from_str(&data).expect("parse vectors")
}

#[test]
fn chains_match_golden_vectors() {
    let vectors = load_vectors();
    let rng = SharedRng::from_seed(vectors.seed);
    for chain_vec in vectors.chains {
        let chain = parse_chain_with_rng(&chain_vec.spec, rng.clone()).expect("parse chain");
        let input = hex_decode(&chain_vec.input_hex).unwrap();
        let mut out = vec![0u8; chain.obfuscated_len(input.len())];
        chain.obfuscate(&mut out, &input);
        assert_eq!(hex_encode(out.clone()), chain_vec.output_hex);

        if !chain_vec.spec.contains("<ds") {
            let mut recovered = vec![0u8; chain.deobfuscated_len(out.len())];
            assert!(
                chain.deobfuscate(&mut recovered, &out),
                "deobfuscate failed for spec {} with output {}",
                chain_vec.spec,
                hex_encode(out),
            );
            assert_eq!(recovered, input);
        }
    }
}

#[test]
fn frames_match_golden_vectors() {
    let vectors = load_vectors();
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
        i1: "<b 0x01><r 4><rc 6><d>".into(),
        i2: String::new(),
        i3: String::new(),
        i4: String::new(),
        i5: String::new(),
    };
    let framer = Framer::new_with_rng(cfg, SharedRng::from_seed(vectors.seed)).expect("framer");
    for frame_vec in vectors.frames {
        let payload = hex_decode(&frame_vec.payload_hex).unwrap();
        let encoded = framer
            .encode_frame(MessageType::Initiation, &payload)
            .expect("encode");
        assert_eq!(hex_encode(&encoded), frame_vec.output_hex);

        let (msg_type, decoded) = framer.decode_frame(&encoded).expect("decode");
        assert_eq!(msg_type as u8, frame_vec.msg_type);
        assert_eq!(decoded, payload);
        assert_eq!(frame_vec.padding, encoded.len().saturating_sub(payload.len() + 5));
    }
}

#[test]
fn transport_matches_golden_vectors() {
    let vectors = load_vectors();
    for transport_vec in vectors.transport {
        let mut rng = ChaCha20Rng::seed_from_u64(vectors.seed);
        let policy = PaddingPolicy {
            enabled: true,
            min: 2,
            max: 6,
            burst_min: 0,
            burst_max: 0,
            burst_prob: 0.0,
        };
        let payload = hex_decode(&transport_vec.payload_hex).unwrap();
        let encoded = build_transport_payload(&payload, transport_vec.counter, &policy, 128, &mut rng)
            .expect("transport encode");
        assert_eq!(hex_encode(&encoded), transport_vec.output_hex);

        let decoded = decode_transport_payload(&encoded, true, Some(|c| transport_vec.counter == Some(c)))
            .expect("transport decode");
        assert_eq!(decoded, payload);
        assert_eq!(transport_vec.padding, encoded.len() - (8 + 2 + payload.len()));
    }
}

#[test]
fn mac1_matches_golden_vectors() {
    let vectors = load_vectors();
    for mac_vec in vectors.mac1 {
        let key = hex_decode(&mac_vec.key_hex).unwrap();
        let input = hex_decode(&mac_vec.input_hex).unwrap();
        let mac = compute_mac1(&key, &input).expect("mac1");
        assert_eq!(hex_encode(&mac), mac_vec.output_hex);
        verify_mac1(&key, &input, &mac).expect("verify");
    }
}

#[test]
fn encrypted_timestamps_match_golden_vectors() {
    let vectors = load_vectors();
    for ts_vec in vectors.enc_timestamp {
        let mut rng = ChaCha20Rng::seed_from_u64(vectors.seed);
        let client_secret = StaticSecret::from(<[u8; 32]>::try_from(hex_decode(&ts_vec.client_secret_hex).unwrap()).unwrap());
        let server_secret = StaticSecret::from(<[u8; 32]>::try_from(hex_decode(&ts_vec.server_secret_hex).unwrap()).unwrap());
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(ts_vec.timestamp);
        let encoded = seal_timestamp(&client_secret, &(&server_secret).into(), ts, &mut rng).expect("seal");

        assert_eq!(hex_encode(encoded.nonce), ts_vec.nonce_hex);
        assert_eq!(hex_encode(encoded.ciphertext.clone()), ts_vec.ciphertext_hex);
        assert_eq!(hex_encode(encoded.ephemeral_pub), ts_vec.ephemeral_hex);

        let opened = open_timestamp(&server_secret, &(&client_secret).into(), &encoded).expect("open");
        assert_eq!(opened, ts);
    }
}

#[test]
fn replay_cache_matches_golden_vectors() {
    let vectors = load_vectors();
    for replay_vec in vectors.replay {
        let mut cache = ReplayCache::new(Duration::from_secs(replay_vec.window_secs), replay_vec.max_entries);
        for event in replay_vec.events {
            let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(event.timestamp);
            let payload = hex_decode(&event.payload_hex).unwrap();
            let mac1 = hex_decode(&event.mac1_hex).unwrap();
            let result = cache.check_and_insert(ts, &payload, &mac1);
            assert_eq!(result.is_ok(), event.accepted, "replay decision mismatch for payload {}", event.payload_hex);
        }
    }
}
