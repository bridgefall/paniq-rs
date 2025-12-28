use std::time::{Duration, SystemTime};

use hex::encode as hex_encode;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use x25519_dalek::StaticSecret;

use paniq::envelope::enc_timestamp::seal_timestamp;
use paniq::envelope::mac1::compute_mac1;
use paniq::envelope::padding::PaddingPolicy;
use paniq::envelope::transport::build_transport_payload;
use paniq::obf::{parse_chain_with_rng, Config, Framer, MessageType, SharedRng};

#[derive(Serialize)]
struct ChainVector {
    spec: String,
    input_hex: String,
    output_hex: String,
}

#[derive(Serialize)]
struct FrameVector {
    msg_type: u8,
    header: String,
    padding: usize,
    payload_hex: String,
    output_hex: String,
}

#[derive(Serialize)]
struct TransportVector {
    counter: Option<u64>,
    padding: usize,
    payload_hex: String,
    output_hex: String,
}

#[derive(Serialize)]
struct Mac1Vector {
    key_hex: String,
    input_hex: String,
    output_hex: String,
}

#[derive(Serialize)]
struct EncTimestampVector {
    client_secret_hex: String,
    server_secret_hex: String,
    timestamp: u64,
    nonce_hex: String,
    ciphertext_hex: String,
    ephemeral_hex: String,
}

#[derive(Serialize)]
struct ReplayEvent {
    timestamp: u64,
    payload_hex: String,
    mac1_hex: String,
    accepted: bool,
}

#[derive(Serialize)]
struct ReplayVector {
    window_secs: u64,
    max_entries: usize,
    events: Vec<ReplayEvent>,
}

#[derive(Serialize)]
struct Vectors {
    seed: u64,
    chains: Vec<ChainVector>,
    frames: Vec<FrameVector>,
    transport: Vec<TransportVector>,
    mac1: Vec<Mac1Vector>,
    enc_timestamp: Vec<EncTimestampVector>,
    replay: Vec<ReplayVector>,
}

fn main() {
    let seed = 12345u64;
    let rng = SharedRng::from_seed(seed);

    // Chain vectors
    let chain_specs = vec![
        ("<b 0x01><r 4><rc 6><d>", "41424344"),
        ("<rd 4><ds><dz 2>", "68656c6c6f"),
    ];
    let mut chains = Vec::new();
    for (spec, input_hex) in chain_specs {
        let chain = parse_chain_with_rng(spec, rng.clone()).expect("parse chain");
        let input = hex::decode(input_hex).expect("decode input");
        let mut out = vec![0u8; chain.obfuscated_len(input.len())];
        chain.obfuscate(&mut out, &input);
        chains.push(ChainVector {
            spec: spec.to_string(),
            input_hex: input_hex.to_string(),
            output_hex: hex_encode(out),
        });
    }

    // Frame vector
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
    let framer = Framer::new_with_rng(cfg, rng.clone()).expect("framer");
    let payload = hex::decode("010203").unwrap();
    let frame = framer
        .encode_frame(MessageType::Initiation, &payload)
        .expect("encode frame");
    let frame_vec = FrameVector {
        msg_type: MessageType::Initiation as u8,
        header: "100".into(),
        padding: 0,
        payload_hex: "010203".into(),
        output_hex: hex_encode(frame),
    };

    // Transport vector
    let mut rng_transport = ChaCha20Rng::seed_from_u64(seed);
    let padding_policy = PaddingPolicy {
        enabled: true,
        min: 2,
        max: 6,
        burst_min: 0,
        burst_max: 0,
        burst_prob: 0.0,
    };
    let transport_payload =
        build_transport_payload(b"abcd", Some(7), &padding_policy, 128, &mut rng_transport)
            .expect("transport");
    let transport_vec = TransportVector {
        counter: Some(7),
        padding: transport_payload.len() - (8 + 2 + 4),
        payload_hex: "61626364".into(),
        output_hex: hex_encode(transport_payload),
    };

    // MAC1 vector
    let mac = compute_mac1(b"0f1e2d3c4b5a6978", b"feedface").expect("mac1");
    let mac_vec = Mac1Vector {
        key_hex: "30663165326433633462356136393738".into(),
        input_hex: "6665656466616365".into(),
        output_hex: hex_encode(mac),
    };

    // Encrypted timestamp vector
    let mut ts_rng = ChaCha20Rng::seed_from_u64(seed);
    let client_secret = StaticSecret::from([3u8; 32]);
    let server_secret = StaticSecret::from([4u8; 32]);
    let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let encoded_ts = seal_timestamp(&client_secret, &(&server_secret).into(), ts, &mut ts_rng)
        .expect("seal timestamp");
    let enc_ts_vec = EncTimestampVector {
        client_secret_hex: hex_encode(client_secret.to_bytes()),
        server_secret_hex: hex_encode(server_secret.to_bytes()),
        timestamp: 1_700_000_000,
        nonce_hex: hex_encode(encoded_ts.nonce),
        ciphertext_hex: hex_encode(&encoded_ts.ciphertext),
        ephemeral_hex: hex_encode(encoded_ts.ephemeral_pub),
    };

    // Replay cache vector
    use paniq::envelope::replay::ReplayCache;

    let replay_mac1 = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
    let base_ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let mut replay_cache = ReplayCache::new(Duration::from_secs(5), 3);
    let replay_payloads = vec![
        (0u64, b"alpha".to_vec()), // first insert
        (0, b"alpha".to_vec()),    // duplicate at same timestamp
        (2, b"beta".to_vec()),     // new payload within window
        (7, b"alpha".to_vec()),    // outside window -> accepted again
        (8, b"gamma".to_vec()),    // fills cache
        (9, b"delta".to_vec()),    // triggers eviction of oldest
    ];
    let mut replay_events = Vec::new();
    for (offset, payload) in replay_payloads {
        let ts = base_ts + Duration::from_secs(offset);
        let accepted = replay_cache
            .check_and_insert(ts, &payload, &replay_mac1)
            .is_ok();
        replay_events.push(ReplayEvent {
            timestamp: 1_000_000 + offset,
            payload_hex: hex_encode(&payload),
            mac1_hex: hex_encode(&replay_mac1),
            accepted,
        });
    }
    let replay_vec = ReplayVector {
        window_secs: 5,
        max_entries: 3,
        events: replay_events,
    };

    let vectors = Vectors {
        seed,
        chains,
        frames: vec![frame_vec],
        transport: vec![transport_vec],
        mac1: vec![mac_vec],
        enc_timestamp: vec![enc_ts_vec],
        replay: vec![replay_vec],
    };

    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}
