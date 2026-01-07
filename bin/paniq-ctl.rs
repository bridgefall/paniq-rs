use base64::Engine;
use clap::{Parser, Subcommand};
use paniq::control::{ControlRequest, ControlResponse};
use paniq::profile::{ObfuscationConfig, Profile, TransportPadding};
use std::io::{Read, Write};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Commands::Ping { socket } => {
            let response = send_command(socket, ControlRequest::Ping).await?;
            match response {
                ControlResponse::Pong => {
                    println!("Pong");
                }
                ControlResponse::Error(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("Unexpected response");
                    std::process::exit(1);
                }
            }
        }
        Commands::Stats { socket } => {
            let response = send_command(socket, ControlRequest::GetStats).await?;
            match response {
                ControlResponse::Stats(stats) => {
                    println!("{}", serde_json::to_string_pretty(&stats)?);
                }
                ControlResponse::Error(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("Unexpected response");
                    std::process::exit(1);
                }
            }
        }
        Commands::Keygen => {
            run_keygen();
        }
        Commands::Headergen {
            width,
            min,
            max,
            distinct_msb,
            json,
        } => {
            run_headergen(width, min, max, distinct_msb, json)?;
        }
        Commands::CreateProfile {
            mtu,
            profile_name,
            proxy_addr,
        } => {
            run_create_profile(mtu, profile_name, proxy_addr)?;
        }
        Commands::ProfileCbor {
            decode,
            input,
            output,
            base64,
        } => {
            run_profile_cbor(decode, input, output, base64)?;
        }
    }

    Ok(())
}

async fn send_command(
    socket_path: PathBuf,
    request: ControlRequest,
) -> Result<ControlResponse, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(&socket_path).await?;
    let bytes = serde_json::to_vec(&request)?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let response: ControlResponse = serde_json::from_slice(&buf)?;

    match &response {
        ControlResponse::Error(e) => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Server error: {}", e),
        )) as Box<dyn std::error::Error>),
        _ => Ok(response),
    }
}

fn run_keygen() {
    let keys = generate_keys();
    println!("server_private_key={}", keys.priv_key);
    println!("server_public_key={}", keys.pub_key);
}

struct KeyPair {
    priv_key: String,
    pub_key: String,
}

fn generate_keys() -> KeyPair {
    let mut priv_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut priv_bytes);

    let secret = x25519_dalek::StaticSecret::from(priv_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);

    KeyPair {
        priv_key: base64::engine::general_purpose::STANDARD.encode(priv_bytes),
        pub_key: base64::engine::general_purpose::STANDARD.encode(public.as_bytes()),
    }
}

#[derive(Debug, Clone, Copy)]
struct HeaderRange {
    start: u32,
    end: u32,
}

fn run_headergen(
    width: u32,
    min: u32,
    max: u32,
    distinct_msb: bool,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ranges = generate_ranges(width, min, max, distinct_msb)?;

    if json {
        for (i, hr) in ranges.iter().enumerate() {
            let key = format!("h{}", i + 1);
            println!("      {:?}: {:?},", key, format!("{}-{}", hr.start, hr.end));
        }
    } else {
        for (i, hr) in ranges.iter().enumerate() {
            println!("h{}={}-{}", i + 1, hr.start, hr.end);
        }
    }

    Ok(())
}

fn generate_ranges(
    width: u32,
    min: u32,
    max: u32,
    distinct_msb: bool,
) -> Result<Vec<HeaderRange>, Box<dyn std::error::Error>> {
    const HEADER_COUNT: usize = 4;
    const MSB_BUCKET_SIZE: u32 = 1 << 24;

    if max < min + width {
        return Err("range bounds too small for width".into());
    }
    if distinct_msb && width >= MSB_BUCKET_SIZE {
        return Err(format!("width must be < {} for distinct-msb", MSB_BUCKET_SIZE).into());
    }

    let mut ranges: Vec<HeaderRange> = Vec::with_capacity(HEADER_COUNT);
    let mut used_msb = std::collections::HashSet::new();
    let mut rng = rand::thread_rng();

    while ranges.len() < HEADER_COUNT {
        let start: u32;
        if distinct_msb {
            let mut msb: u8;
            loop {
                msb = (rand::Rng::gen::<u32>(&mut rng) >> 24) as u8;
                if !used_msb.contains(&msb) {
                    break;
                }
            }

            let bucket_min = (msb as u32) << 24;
            let bucket_max = bucket_min + MSB_BUCKET_SIZE - 1;

            if bucket_max <= bucket_min + width {
                return Err("bucket too small for width".into());
            }

            start = rand::Rng::gen_range(&mut rng, bucket_min..=(bucket_max - width));
            used_msb.insert(msb);
        } else {
            start = rand::Rng::gen_range(&mut rng, min..=(max - width));
        }

        let hr = HeaderRange {
            start,
            end: start + width,
        };

        if ranges
            .iter()
            .any(|r| hr.start <= r.end && hr.end >= r.start)
        {
            if distinct_msb {
                used_msb.remove(&((start >> 24) as u8));
            }
            continue;
        }
        ranges.push(hr);
    }

    ranges.sort_by_key(|r| r.start);
    Ok(ranges)
}

fn run_create_profile(
    mtu: usize,
    profile_name: Option<String>,
    proxy_addr: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if mtu < 1280 {
        return Err("mtu must be >= 1280".into());
    }

    let keys = generate_keys();
    let mut rng = rand::thread_rng();

    let width = rand::Rng::gen_range(&mut rng, 512..=2048);
    let ranges = generate_ranges(width, 1, u32::MAX, true)?;

    let now = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let name = profile_name.unwrap_or_else(|| format!("bf-{}", now));
    let addr = proxy_addr.unwrap_or_else(|| {
        eprintln!("warning: proxy_addr is empty; set --proxy-addr to generate a usable profile");
        String::new()
    });

    // Roughly replicate the Go buildSafeObf logic
    let jc = rand::Rng::gen_range(&mut rng, 3..=5);
    let jmin = rand::Rng::gen_range(&mut rng, 200..=600);
    let jmax_upper = 1400.min(mtu.saturating_sub(100).max(900));
    let mut jmax = rand::Rng::gen_range(&mut rng, 900..=jmax_upper);
    if jmax <= jmin {
        jmax = (jmin + rand::Rng::gen_range(&mut rng, 200..=600)).min(jmax_upper);
    }

    let s1 = rand::Rng::gen_range(&mut rng, 200..=520);
    let s2 = rand::Rng::gen_range(&mut rng, 260..=640);
    let s3 = rand::Rng::gen_range(&mut rng, 120..=360);
    let mut s4 = rand::Rng::gen_range(&mut rng, 20..=80);

    let max_s4 = mtu.saturating_sub(1200 + 6);
    if s4 > max_s4 {
        s4 = max_s4;
    }

    let overhead = s4 + 4 + 2;
    let budget = mtu.saturating_sub(overhead);
    if budget < 1200 {
        return Err("mtu too small for minimum payload budget".into());
    }
    let max_payload = 1200;
    let headroom = budget.saturating_sub(max_payload);

    let padding = build_padding(headroom);

    let profile = Profile {
        name,
        proxy_addr: addr,
        handshake_timeout: Some(std::time::Duration::from_secs(5)),
        handshake_attempts: 3,
        preamble_delay_ms: Some(5),
        preamble_jitter_ms: Some(5),
        kcp: Some(paniq::profile::KcpConfig {
            max_packet_size: mtu,
            max_payload,
            keepalive: std::time::Duration::from_secs(20),
            idle_timeout: std::time::Duration::from_secs(120),
            max_streams: 256,
            ..Default::default()
        }),
        transport_padding: Some(padding),
        obfuscation: ObfuscationConfig {
            jc: jc as i32,
            jmin: jmin as i32,
            jmax: jmax as i32,
            s1: s1 as i32,
            s2: s2 as i32,
            s3: s3 as i32,
            s4: s4 as i32,
            h1: format!("{}-{}", ranges[0].start, ranges[0].end),
            h2: format!("{}-{}", ranges[1].start, ranges[1].end),
            h3: format!("{}-{}", ranges[2].start, ranges[2].end),
            h4: format!("{}-{}", ranges[3].start, ranges[3].end),
            i1: "<t>".to_string(),
            server_private_key: keys.priv_key,
            server_public_key: keys.pub_key,
            signature_validate: true,
            require_timestamp: Some(true),
            encrypted_timestamp: true,
            require_encrypted_timestamp: true,
            skew_soft_seconds: 15,
            skew_hard_seconds: 30,
            replay_window_seconds: 30,
            replay_cache_size: 4096,
            rate_limit_pps: 50,
            rate_limit_burst: 20,
            ..Default::default()
        },
    };

    let json_out = serde_json::to_string_pretty(&profile)?;
    println!("{}", json_out);

    Ok(())
}

fn build_padding(headroom: usize) -> TransportPadding {
    if headroom == 0 {
        return TransportPadding {
            pad_min: 0,
            pad_max: 0,
            pad_burst_min: 0,
            pad_burst_max: 0,
            pad_burst_prob: 0.0,
        };
    }

    let pad_min = 16.min(headroom);
    let mut pad_max = 96.min(headroom);
    if headroom < 16 {
        return TransportPadding {
            pad_min: 0,
            pad_max: headroom,
            pad_burst_min: 0,
            pad_burst_max: 0,
            pad_burst_prob: 0.0,
        };
    }
    if pad_max < pad_min {
        pad_max = pad_min;
    }

    let mut pad_burst_min = 96.min(headroom);
    let mut pad_burst_max = 128.min(headroom);
    let mut pad_burst_prob = 0.02;

    if headroom < 96 {
        pad_burst_min = 0;
        pad_burst_max = 0;
        pad_burst_prob = 0.0;
    }

    TransportPadding {
        pad_min,
        pad_max,
        pad_burst_min,
        pad_burst_max,
        pad_burst_prob,
    }
}

fn run_profile_cbor(
    decode: bool,
    input_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    use_base64: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    if let Some(path) = input_path {
        std::fs::File::open(path)?.read_to_end(&mut input)?;
    } else {
        std::io::stdin().read_to_end(&mut input)?;
    }

    let output_data = if decode {
        let cbor_bytes = if use_base64 {
            let s = String::from_utf8(input)?;
            let trimmed = s.trim().replace(|c: char| c.is_whitespace(), "");
            base64::engine::general_purpose::STANDARD.decode(trimmed)?
        } else {
            input
        };

        let profile = decode_compact_profile(&cbor_bytes)?;
        serde_json::to_vec_pretty(&profile)?
    } else {
        let profile: Profile = serde_json::from_slice(&input)?;
        let cbor_bytes = encode_compact_profile(&profile)?;

        if use_base64 {
            base64::engine::general_purpose::STANDARD
                .encode(cbor_bytes)
                .into_bytes()
        } else {
            cbor_bytes
        }
    };

    if let Some(path) = output_path {
        std::fs::File::create(path)?.write_all(&output_data)?;
    } else {
        std::io::stdout().write_all(&output_data)?;
        if !decode && !use_base64 {
            // Don't print newline if it's raw binary CBOR to stdout
        } else {
            println!();
        }
    }

    Ok(())
}

// CBOR Key constants
const KEY_VERSION: u64 = 0;
const KEY_NAME: u64 = 1;
const KEY_PROXY_ADDR: u64 = 2;
const KEY_HANDSHAKE_TIMEOUT: u64 = 3;
const KEY_HANDSHAKE_ATTEMPTS: u64 = 4;
const KEY_PREAMBLE_DELAY: u64 = 5;
const KEY_PREAMBLE_JITTER: u64 = 6;
const KEY_QUIC: u64 = 7;
const KEY_OBFUSCATION: u64 = 8;
const KEY_TRANSPORT_PADDING: u64 = 9;

const KEY_QUIC_MAX_PACKET_SIZE: u64 = 1;
const KEY_QUIC_MAX_PAYLOAD: u64 = 2;
const KEY_QUIC_KEEP_ALIVE: u64 = 3;
const KEY_QUIC_IDLE_TIMEOUT: u64 = 4;
const KEY_QUIC_MAX_STREAMS: u64 = 5;

const KEY_OBF_JC: u64 = 1;
const KEY_OBF_JMIN: u64 = 2;
const KEY_OBF_JMAX: u64 = 3;
const KEY_OBF_S1: u64 = 4;
const KEY_OBF_S2: u64 = 5;
const KEY_OBF_S3: u64 = 6;
const KEY_OBF_S4: u64 = 7;
const KEY_OBF_H1: u64 = 8;
const KEY_OBF_H2: u64 = 9;
const KEY_OBF_H3: u64 = 10;
const KEY_OBF_H4: u64 = 11;
const KEY_OBF_I1: u64 = 12;
const KEY_OBF_I2: u64 = 13;
const KEY_OBF_I3: u64 = 14;
const KEY_OBF_I4: u64 = 15;
const KEY_OBF_I5: u64 = 16;
const KEY_OBF_SERVER_PRIVATE_KEY: u64 = 17;
const KEY_OBF_SERVER_PUBLIC_KEY: u64 = 18;
const KEY_OBF_SIGNATURE_VALIDATE: u64 = 19;
const KEY_OBF_REQUIRE_TIMESTAMP: u64 = 20;
const KEY_OBF_ENCRYPTED_TIMESTAMP: u64 = 21;
const KEY_OBF_REQUIRE_ENCRYPTED_TIMESTAMP: u64 = 22;
const KEY_OBF_LEGACY_MODE_ENABLED: u64 = 23;
const KEY_OBF_SKEW_SOFT_SECONDS: u64 = 26;
const KEY_OBF_SKEW_HARD_SECONDS: u64 = 27;
const KEY_OBF_REPLAY_WINDOW_SECONDS: u64 = 28;
const KEY_OBF_REPLAY_CACHE_SIZE: u64 = 29;
const KEY_OBF_TRANSPORT_REPLAY: u64 = 30;
const KEY_OBF_TRANSPORT_REPLAY_LIMIT: u64 = 31;
const KEY_OBF_RATE_LIMIT_PPS: u64 = 32;
const KEY_OBF_RATE_LIMIT_BURST: u64 = 33;

const KEY_PAD_MIN: u64 = 1;
const KEY_PAD_MAX: u64 = 2;
const KEY_PAD_BURST_MIN: u64 = 3;
const KEY_PAD_BURST_MAX: u64 = 4;
const KEY_PAD_BURST_PROB: u64 = 5;

// Defaults from Go implementation
const DEFAULT_HANDSHAKE_ATTEMPTS: usize = 3;
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 5000;
const DEFAULT_QUIC_MAX_PACKET_SIZE: usize = 1350;
const DEFAULT_QUIC_KEEP_ALIVE_MS: u64 = 20000;
const DEFAULT_QUIC_IDLE_TIMEOUT_MS: u64 = 120000;
const DEFAULT_QUIC_MAX_STREAMS: usize = 256;

// Padding defaults
const DEFAULT_PAD_MIN: usize = 16;
const DEFAULT_PAD_MAX: usize = 96;
const DEFAULT_PAD_BURST_MIN: usize = 96;
const DEFAULT_PAD_BURST_MAX: usize = 104;
const DEFAULT_PAD_BURST_PROB: f64 = 0.02;

fn encode_compact_profile(p: &Profile) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use ciborium::value::Value;
    use std::collections::BTreeMap;

    let mut map = BTreeMap::new();
    map.insert(KEY_VERSION, Value::Integer(1.into()));

    if !p.name.is_empty() {
        map.insert(KEY_NAME, Value::Text(p.name.clone()));
    }

    map.insert(KEY_PROXY_ADDR, Value::Text(p.proxy_addr.clone()));

    if let Some(d) = p.handshake_timeout {
        let ms = d.as_millis() as u64;
        if ms != DEFAULT_HANDSHAKE_TIMEOUT_MS {
            map.insert(KEY_HANDSHAKE_TIMEOUT, Value::Integer(ms.into()));
        }
    }

    if p.handshake_attempts != DEFAULT_HANDSHAKE_ATTEMPTS {
        map.insert(
            KEY_HANDSHAKE_ATTEMPTS,
            Value::Integer((p.handshake_attempts as u64).into()),
        );
    }

    if let Some(ms) = p.preamble_delay_ms {
        if ms > 0 {
            map.insert(KEY_PREAMBLE_DELAY, Value::Integer(ms.into()));
        }
    }
    if let Some(ms) = p.preamble_jitter_ms {
        if ms > 0 {
            map.insert(KEY_PREAMBLE_JITTER, Value::Integer(ms.into()));
        }
    }

    if let Some(kcp) = &p.kcp {
        let mut qmap = BTreeMap::new();
        if kcp.max_packet_size != DEFAULT_QUIC_MAX_PACKET_SIZE {
            qmap.insert(
                KEY_QUIC_MAX_PACKET_SIZE,
                Value::Integer((kcp.max_packet_size as u64).into()),
            );
        }
        if kcp.max_payload > 0 {
            qmap.insert(
                KEY_QUIC_MAX_PAYLOAD,
                Value::Integer((kcp.max_payload as u64).into()),
            );
        }
        let ks = kcp.keepalive.as_millis() as u64;
        if ks != DEFAULT_QUIC_KEEP_ALIVE_MS {
            qmap.insert(KEY_QUIC_KEEP_ALIVE, Value::Integer(ks.into()));
        }
        let is = kcp.idle_timeout.as_millis() as u64;
        if is != DEFAULT_QUIC_IDLE_TIMEOUT_MS {
            qmap.insert(KEY_QUIC_IDLE_TIMEOUT, Value::Integer(is.into()));
        }
        if kcp.max_streams != DEFAULT_QUIC_MAX_STREAMS {
            qmap.insert(
                KEY_QUIC_MAX_STREAMS,
                Value::Integer((kcp.max_streams as u64).into()),
            );
        }
        if !qmap.is_empty() {
            let qv = Value::Map(
                qmap.into_iter()
                    .map(|(k, v)| (Value::Integer(k.into()), v))
                    .collect(),
            );
            map.insert(KEY_QUIC, qv);
        }
    }

    // Obfuscation
    let mut omap = BTreeMap::new();
    let o = &p.obfuscation;
    if o.jc != 0 {
        omap.insert(KEY_OBF_JC, Value::Integer(o.jc.into()));
    }
    if o.jmin != 0 {
        omap.insert(KEY_OBF_JMIN, Value::Integer(o.jmin.into()));
    }
    if o.jmax != 0 {
        omap.insert(KEY_OBF_JMAX, Value::Integer(o.jmax.into()));
    }
    if o.s1 != 0 {
        omap.insert(KEY_OBF_S1, Value::Integer(o.s1.into()));
    }
    if o.s2 != 0 {
        omap.insert(KEY_OBF_S2, Value::Integer(o.s2.into()));
    }
    if o.s3 != 0 {
        omap.insert(KEY_OBF_S3, Value::Integer(o.s3.into()));
    }
    if o.s4 != 0 {
        omap.insert(KEY_OBF_S4, Value::Integer(o.s4.into()));
    }
    if !o.h1.is_empty() {
        omap.insert(KEY_OBF_H1, Value::Text(o.h1.clone()));
    }
    if !o.h2.is_empty() {
        omap.insert(KEY_OBF_H2, Value::Text(o.h2.clone()));
    }
    if !o.h3.is_empty() {
        omap.insert(KEY_OBF_H3, Value::Text(o.h3.clone()));
    }
    if !o.h4.is_empty() {
        omap.insert(KEY_OBF_H4, Value::Text(o.h4.clone()));
    }
    if !o.i1.is_empty() {
        omap.insert(KEY_OBF_I1, Value::Text(o.i1.clone()));
    }
    if !o.i2.is_empty() {
        omap.insert(KEY_OBF_I2, Value::Text(o.i2.clone()));
    }
    if !o.i3.is_empty() {
        omap.insert(KEY_OBF_I3, Value::Text(o.i3.clone()));
    }
    if !o.i4.is_empty() {
        omap.insert(KEY_OBF_I4, Value::Text(o.i4.clone()));
    }
    if !o.i5.is_empty() {
        omap.insert(KEY_OBF_I5, Value::Text(o.i5.clone()));
    }

    if !o.server_private_key.is_empty() {
        let raw = base64::engine::general_purpose::STANDARD.decode(&o.server_private_key)?;
        omap.insert(KEY_OBF_SERVER_PRIVATE_KEY, Value::Bytes(raw));
    }
    if !o.server_public_key.is_empty() {
        let raw = base64::engine::general_purpose::STANDARD.decode(&o.server_public_key)?;
        omap.insert(KEY_OBF_SERVER_PUBLIC_KEY, Value::Bytes(raw));
    }

    omap.insert(
        KEY_OBF_SIGNATURE_VALIDATE,
        Value::Bool(o.signature_validate),
    );
    if let Some(v) = o.require_timestamp {
        omap.insert(KEY_OBF_REQUIRE_TIMESTAMP, Value::Bool(v));
    }
    omap.insert(
        KEY_OBF_ENCRYPTED_TIMESTAMP,
        Value::Bool(o.encrypted_timestamp),
    );
    omap.insert(
        KEY_OBF_REQUIRE_ENCRYPTED_TIMESTAMP,
        Value::Bool(o.require_encrypted_timestamp),
    );
    if o.legacy_mode_enabled {
        omap.insert(KEY_OBF_LEGACY_MODE_ENABLED, Value::Bool(true));
    }
    if o.skew_soft_seconds != 15 {
        omap.insert(
            KEY_OBF_SKEW_SOFT_SECONDS,
            Value::Integer(o.skew_soft_seconds.into()),
        );
    }
    if o.skew_hard_seconds != 30 {
        omap.insert(
            KEY_OBF_SKEW_HARD_SECONDS,
            Value::Integer(o.skew_hard_seconds.into()),
        );
    }
    if o.replay_window_seconds != 30 {
        omap.insert(
            KEY_OBF_REPLAY_WINDOW_SECONDS,
            Value::Integer((o.replay_window_seconds as u64).into()),
        );
    }
    if o.replay_cache_size != 4096 {
        omap.insert(
            KEY_OBF_REPLAY_CACHE_SIZE,
            Value::Integer((o.replay_cache_size as u64).into()),
        );
    }
    if o.transport_replay {
        omap.insert(KEY_OBF_TRANSPORT_REPLAY, Value::Bool(true));
    }
    if o.transport_replay_limit != 0 {
        omap.insert(
            KEY_OBF_TRANSPORT_REPLAY_LIMIT,
            Value::Integer(o.transport_replay_limit.into()),
        );
    }
    if o.rate_limit_pps != 200 {
        omap.insert(
            KEY_OBF_RATE_LIMIT_PPS,
            Value::Integer(o.rate_limit_pps.into()),
        );
    }
    if o.rate_limit_burst != 500 {
        omap.insert(
            KEY_OBF_RATE_LIMIT_BURST,
            Value::Integer(o.rate_limit_burst.into()),
        );
    }

    if !omap.is_empty() {
        let ov = Value::Map(
            omap.into_iter()
                .map(|(k, v)| (Value::Integer(k.into()), v))
                .collect(),
        );
        map.insert(KEY_OBFUSCATION, ov);
    }

    if let Some(tp) = &p.transport_padding {
        let mut pmap = BTreeMap::new();
        if tp.pad_min != DEFAULT_PAD_MIN {
            pmap.insert(KEY_PAD_MIN, Value::Integer((tp.pad_min as u64).into()));
        }
        if tp.pad_max != DEFAULT_PAD_MAX {
            pmap.insert(KEY_PAD_MAX, Value::Integer((tp.pad_max as u64).into()));
        }
        if tp.pad_burst_min != DEFAULT_PAD_BURST_MIN {
            pmap.insert(
                KEY_PAD_BURST_MIN,
                Value::Integer((tp.pad_burst_min as u64).into()),
            );
        }
        if tp.pad_burst_max != DEFAULT_PAD_BURST_MAX {
            pmap.insert(
                KEY_PAD_BURST_MAX,
                Value::Integer((tp.pad_burst_max as u64).into()),
            );
        }
        if tp.pad_burst_prob != DEFAULT_PAD_BURST_PROB {
            pmap.insert(KEY_PAD_BURST_PROB, Value::Float(tp.pad_burst_prob));
        }
        if !pmap.is_empty() {
            let pv = Value::Map(
                pmap.into_iter()
                    .map(|(k, v)| (Value::Integer(k.into()), v))
                    .collect(),
            );
            map.insert(KEY_TRANSPORT_PADDING, pv);
        }
    }

    let mut buf = Vec::new();
    let final_map = Value::Map(
        map.into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect(),
    );
    ciborium::into_writer(&final_map, &mut buf)?;
    Ok(buf)
}

fn decode_compact_profile(data: &[u8]) -> Result<Profile, Box<dyn std::error::Error>> {
    use ciborium::value::Value;

    let val: Value = ciborium::from_reader(data)?;
    let map = match val {
        Value::Map(m) => m,
        _ => return Err("expected CBOR map".into()),
    };

    let get_kv = |k: u64| {
        map.iter()
            .find(|(kv, _)| match kv {
                Value::Integer(ki) => {
                    let i: i64 = (*ki).try_into().unwrap_or_default(); // Use i64
                    i == k as i64 // Compare with i64
                }
                _ => false,
            })
            .map(|(_, v)| v)
    };

    let version = get_kv(KEY_VERSION)
        .and_then(|v| v.as_integer())
        .map(|i| {
            let i: u64 = i.try_into().unwrap_or_default(); // Use u64
            i
        })
        .ok_or("missing version")?;
    if version != 1 {
        return Err(format!("unsupported version {}", version).into());
    }

    let mut out = Profile {
        name: String::new(),
        proxy_addr: String::new(),
        handshake_timeout: None,
        handshake_attempts: DEFAULT_HANDSHAKE_ATTEMPTS,
        preamble_delay_ms: None,
        preamble_jitter_ms: None,
        kcp: None,
        transport_padding: None,
        obfuscation: ObfuscationConfig::default(),
    };

    if let Some(v) = get_kv(KEY_NAME).and_then(|v| v.as_text()) {
        out.name = v.to_string();
    }
    if let Some(v) = get_kv(KEY_PROXY_ADDR).and_then(|v| v.as_text()) {
        out.proxy_addr = v.to_string();
    }
    if let Some(v) = get_kv(KEY_HANDSHAKE_TIMEOUT).and_then(|v| v.as_integer()) {
        let ms: u64 = v.try_into().unwrap_or_default(); // Use u64
        out.handshake_timeout = Some(std::time::Duration::from_millis(ms));
    }
    if let Some(v) = get_kv(KEY_HANDSHAKE_ATTEMPTS).and_then(|v| v.as_integer()) {
        let val: u64 = v.try_into().unwrap_or_default(); // Use u64
        out.handshake_attempts = val as usize;
    }
    if let Some(v) = get_kv(KEY_PREAMBLE_DELAY).and_then(|v| v.as_integer()) {
        let val: u64 = v.try_into().unwrap_or_default(); // Use u64
        out.preamble_delay_ms = Some(val);
    }
    if let Some(v) = get_kv(KEY_PREAMBLE_JITTER).and_then(|v| v.as_integer()) {
        let val: u64 = v.try_into().unwrap_or_default(); // Use u64
        out.preamble_jitter_ms = Some(val);
    }

    if let Some(v) = get_kv(KEY_QUIC) {
        if let Value::Map(m) = v {
            let get_qv = |k: u64| {
                m.iter()
                    .find(|(kv, _)| match kv {
                        Value::Integer(ki) => {
                            let i: i64 = (*ki).try_into().unwrap_or_default(); // Use i64
                            i == k as i64 // Compare with i64
                        }
                        _ => false,
                    })
                    .map(|(_, v)| v)
            };

            let mut q = paniq::profile::KcpConfig {
                max_packet_size: DEFAULT_QUIC_MAX_PACKET_SIZE,
                max_payload: 1200, // standard default
                keepalive: std::time::Duration::from_millis(DEFAULT_QUIC_KEEP_ALIVE_MS),
                idle_timeout: std::time::Duration::from_millis(DEFAULT_QUIC_IDLE_TIMEOUT_MS),
                max_streams: DEFAULT_QUIC_MAX_STREAMS,
                ..Default::default()
            };

            if let Some(sv) = get_qv(KEY_QUIC_MAX_PACKET_SIZE).and_then(|v| v.as_integer()) {
                let val: u64 = sv.try_into().unwrap_or_default(); // Use u64
                q.max_packet_size = val as usize;
            }
            if let Some(sv) = get_qv(KEY_QUIC_MAX_PAYLOAD).and_then(|v| v.as_integer()) {
                let val: u64 = sv.try_into().unwrap_or_default(); // Use u64
                q.max_payload = val as usize;
            }
            if let Some(sv) = get_qv(KEY_QUIC_KEEP_ALIVE).and_then(|v| v.as_integer()) {
                let val: u64 = sv.try_into().unwrap_or_default(); // Use u64
                q.keepalive = std::time::Duration::from_millis(val);
            }
            if let Some(sv) = get_qv(KEY_QUIC_IDLE_TIMEOUT).and_then(|v| v.as_integer()) {
                let val: u64 = sv.try_into().unwrap_or_default(); // Use u64
                q.idle_timeout = std::time::Duration::from_millis(val);
            }
            if let Some(sv) = get_qv(KEY_QUIC_MAX_STREAMS).and_then(|v| v.as_integer()) {
                let val: u64 = sv.try_into().unwrap_or_default(); // Use u64
                q.max_streams = val as usize;
            }
            out.kcp = Some(q);
        }
    }

    if let Some(v) = get_kv(KEY_OBFUSCATION) {
        if let Value::Map(m) = v {
            let get_ov = |k: u64| {
                m.iter()
                    .find(|(kv, _)| match kv {
                        Value::Integer(ki) => {
                            let i: i64 = (*ki).try_into().unwrap_or_default(); // Use i64
                            i == k as i64 // Compare with i64
                        }
                        _ => false,
                    })
                    .map(|(_, v)| v)
            };

            let mut o = ObfuscationConfig::default();
            if let Some(sv) = get_ov(KEY_OBF_JC).and_then(|v| v.as_integer()) {
                o.jc = sv.try_into().unwrap_or_default();
            } // Use i64
            if let Some(sv) = get_ov(KEY_OBF_JMIN).and_then(|v| v.as_integer()) {
                o.jmin = sv.try_into().unwrap_or_default();
            } // Use i64
            if let Some(sv) = get_ov(KEY_OBF_JMAX).and_then(|v| v.as_integer()) {
                o.jmax = sv.try_into().unwrap_or_default();
            } // Use i64
            if let Some(sv) = get_ov(KEY_OBF_S1).and_then(|v| v.as_integer()) {
                o.s1 = sv.try_into().unwrap_or_default();
            } // Use i64
            if let Some(sv) = get_ov(KEY_OBF_S2).and_then(|v| v.as_integer()) {
                o.s2 = sv.try_into().unwrap_or_default();
            } // Use i64
            if let Some(sv) = get_ov(KEY_OBF_S3).and_then(|v| v.as_integer()) {
                o.s3 = sv.try_into().unwrap_or_default();
            } // Use i64
            if let Some(sv) = get_ov(KEY_OBF_S4).and_then(|v| v.as_integer()) {
                o.s4 = sv.try_into().unwrap_or_default();
            } // Use i64
            if let Some(sv) = get_ov(KEY_OBF_H1).and_then(|v| v.as_text()) {
                o.h1 = sv.to_string();
            }
            if let Some(sv) = get_ov(KEY_OBF_H2).and_then(|v| v.as_text()) {
                o.h2 = sv.to_string();
            }
            if let Some(sv) = get_ov(KEY_OBF_H3).and_then(|v| v.as_text()) {
                o.h3 = sv.to_string();
            }
            if let Some(sv) = get_ov(KEY_OBF_H4).and_then(|v| v.as_text()) {
                o.h4 = sv.to_string();
            }
            if let Some(sv) = get_ov(KEY_OBF_I1).and_then(|v| v.as_text()) {
                o.i1 = sv.to_string();
            }
            if let Some(sv) = get_ov(KEY_OBF_I2).and_then(|v| v.as_text()) {
                o.i2 = sv.to_string();
            }
            if let Some(sv) = get_ov(KEY_OBF_I3).and_then(|v| v.as_text()) {
                o.i3 = sv.to_string();
            }
            if let Some(sv) = get_ov(KEY_OBF_I4).and_then(|v| v.as_text()) {
                o.i4 = sv.to_string();
            }
            if let Some(sv) = get_ov(KEY_OBF_I5).and_then(|v| v.as_text()) {
                o.i5 = sv.to_string();
            }

            if let Some(sv) = get_ov(KEY_OBF_SERVER_PRIVATE_KEY).and_then(|v| v.as_bytes()) {
                o.server_private_key = base64::engine::general_purpose::STANDARD.encode(sv);
            }
            if let Some(sv) = get_ov(KEY_OBF_SERVER_PUBLIC_KEY).and_then(|v| v.as_bytes()) {
                o.server_public_key = base64::engine::general_purpose::STANDARD.encode(sv);
            }

            if let Some(sv) = get_ov(KEY_OBF_SIGNATURE_VALIDATE).and_then(|v| v.as_bool()) {
                o.signature_validate = sv;
            }
            if let Some(sv) = get_ov(KEY_OBF_REQUIRE_TIMESTAMP).and_then(|v| v.as_bool()) {
                o.require_timestamp = Some(sv);
            }
            if let Some(sv) = get_ov(KEY_OBF_ENCRYPTED_TIMESTAMP).and_then(|v| v.as_bool()) {
                o.encrypted_timestamp = sv;
            }
            if let Some(sv) = get_ov(KEY_OBF_REQUIRE_ENCRYPTED_TIMESTAMP).and_then(|v| v.as_bool())
            {
                o.require_encrypted_timestamp = sv;
            }
            if let Some(sv) = get_ov(KEY_OBF_LEGACY_MODE_ENABLED).and_then(|v| v.as_bool()) {
                o.legacy_mode_enabled = sv;
            }

            if let Some(sv) = get_ov(KEY_OBF_SKEW_SOFT_SECONDS).and_then(|v| v.as_integer()) {
                o.skew_soft_seconds = sv.try_into().unwrap_or_default(); // Use i64
            }
            if let Some(sv) = get_ov(KEY_OBF_SKEW_HARD_SECONDS).and_then(|v| v.as_integer()) {
                o.skew_hard_seconds = sv.try_into().unwrap_or_default(); // Use i64
            }
            if let Some(sv) = get_ov(KEY_OBF_REPLAY_WINDOW_SECONDS).and_then(|v| v.as_integer()) {
                o.replay_window_seconds = sv.try_into().unwrap_or_default(); // Use u64
            }
            if let Some(sv) = get_ov(KEY_OBF_REPLAY_CACHE_SIZE).and_then(|v| v.as_integer()) {
                o.replay_cache_size = sv.try_into().unwrap_or_default(); // Use u64
            }
            if let Some(sv) = get_ov(KEY_OBF_TRANSPORT_REPLAY).and_then(|v| v.as_bool()) {
                o.transport_replay = sv;
            }
            if let Some(sv) = get_ov(KEY_OBF_TRANSPORT_REPLAY_LIMIT).and_then(|v| v.as_integer()) {
                o.transport_replay_limit = sv.try_into().unwrap_or_default(); // Use u64
            }
            if let Some(sv) = get_ov(KEY_OBF_RATE_LIMIT_PPS).and_then(|v| v.as_integer()) {
                o.rate_limit_pps = sv.try_into().unwrap_or_default(); // Use u64
            }
            if let Some(sv) = get_ov(KEY_OBF_RATE_LIMIT_BURST).and_then(|v| v.as_integer()) {
                o.rate_limit_burst = sv.try_into().unwrap_or_default(); // Use u64
            }

            out.obfuscation = o;
        }
    }

    if let Some(v) = get_kv(KEY_TRANSPORT_PADDING) {
        if let Value::Map(m) = v {
            let get_pv = |k: u64| {
                m.iter()
                    .find(|(kv, _)| match kv {
                        Value::Integer(ki) => {
                            let i: i64 = (*ki).try_into().unwrap_or_default(); // Use i64
                            i == k as i64 // Compare with i64
                        }
                        _ => false,
                    })
                    .map(|(_, v)| v)
            };

            let mut t = TransportPadding {
                pad_min: DEFAULT_PAD_MIN,
                pad_max: DEFAULT_PAD_MAX,
                pad_burst_min: DEFAULT_PAD_BURST_MIN,
                pad_burst_max: DEFAULT_PAD_BURST_MAX,
                pad_burst_prob: DEFAULT_PAD_BURST_PROB,
            };

            if let Some(sv) = get_pv(KEY_PAD_MIN).and_then(|v| v.as_integer()) {
                t.pad_min = sv.try_into().unwrap_or_default();
            } // Use u64
            if let Some(sv) = get_pv(KEY_PAD_MAX).and_then(|v| v.as_integer()) {
                t.pad_max = sv.try_into().unwrap_or_default();
            } // Use u64
            if let Some(sv) = get_pv(KEY_PAD_BURST_MIN).and_then(|v| v.as_integer()) {
                t.pad_burst_min = sv.try_into().unwrap_or_default();
            } // Use u64
            if let Some(sv) = get_pv(KEY_PAD_BURST_MAX).and_then(|v| v.as_integer()) {
                t.pad_burst_max = sv.try_into().unwrap_or_default();
            } // Use u64
            if let Some(sv) = get_pv(KEY_PAD_BURST_PROB).and_then(|v| v.as_float()) {
                t.pad_burst_prob = sv;
            }
            out.transport_padding = Some(t);
        }
    }

    Ok(out)
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Paniq control tool", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Ping the daemon")]
    Ping {
        #[arg(short, long, help = "Path to control Unix domain socket")]
        socket: PathBuf,
    },
    #[command(about = "Get daemon statistics")]
    Stats {
        #[arg(short, long, help = "Path to control Unix domain socket")]
        socket: PathBuf,
    },
    #[command(about = "Generate server keypair")]
    Keygen,
    #[command(about = "Generate header ranges")]
    Headergen {
        #[arg(long, default_value = "1024", help = "range width in uint32 units")]
        width: u32,
        #[arg(long, default_value = "1", help = "minimum start value")]
        min: u32,
        #[arg(long, default_value = "4294967295", help = "maximum end value")]
        max: u32,
        #[arg(
            long,
            default_value = "true",
            help = "ensure distinct high-order byte per header"
        )]
        distinct_msb: bool,
        #[arg(long, default_value = "true", help = "output as JSON key/value lines")]
        json: bool,
    },
    #[command(about = "Generate a safe randomized profile")]
    CreateProfile {
        #[arg(
            long,
            default_value = "1420",
            help = "path MTU budget for max_packet_size"
        )]
        mtu: usize,
        #[arg(long, help = "optional profile name")]
        profile_name: Option<String>,
        #[arg(long, help = "optional proxy server address (host:port)")]
        proxy_addr: Option<String>,
    },
    #[command(about = "Encode/decode profile CBOR")]
    ProfileCbor {
        #[arg(long, help = "decode CBOR into JSON")]
        decode: bool,
        #[arg(long, help = "input file (defaults to stdin)")]
        input: Option<PathBuf>,
        #[arg(long, help = "output file (defaults to stdout)")]
        output: Option<PathBuf>,
        #[arg(long, help = "read/write base64-wrapped CBOR")]
        base64: bool,
    },
}
