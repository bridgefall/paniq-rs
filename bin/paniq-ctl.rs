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
        ControlResponse::Error(e) => Err(Box::new(std::io::Error::other(format!(
            "Server error: {}",
            e
        ))) as Box<dyn std::error::Error>),
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

        let profile = paniq::profile::cbor::decode_compact_profile(&cbor_bytes)
            .map_err(|e| format!("CBOR decode error: {}", e))?;
        serde_json::to_vec_pretty(&profile)?
    } else {
        let profile: Profile = serde_json::from_slice(&input)?;
        let cbor_bytes = paniq::profile::cbor::encode_compact_profile(&profile)
            .map_err(|e| format!("CBOR encode error: {}", e))?;

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
