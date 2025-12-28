use std::process::{Command, Stdio, Child};
use std::time::Duration;
use std::path::PathBuf;
// use std::io::Write;
use std::net::TcpListener;

struct ChildGuard {
    child: Child,
    name: String,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        println!("Killed {}", self.name);
    }
}

fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
async fn test_real_binaries_curl() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_dir = PathBuf::from(&manifest_dir).join("target/debug");

    // 1. Build binaries to ensure they are fresh
    println!("Building binaries...");
    let status = Command::new("cargo")
        .args(&["build", "--bin", "proxy-server", "--bin", "socks5d", "--features", "socks5,quic,rcgen"])
        .current_dir(&manifest_dir)
        .status()
        .expect("Failed to run cargo build");
    assert!(status.success(), "Cargo build failed");

    // 2. Setup ports and profile
    let proxy_port = get_free_port();
    let socks_port = get_free_port();

    // We pick a different socks port to avoid conflict if finding free port races?
    // loop until different?
    let mut socks_port_final = socks_port;
    if proxy_port == socks_port {
        socks_port_final = get_free_port();
    }
    let socks_port = socks_port_final;

    println!("Ports: Proxy={}, Socks={}", proxy_port, socks_port);

    // Create temp profile
    let profile_content = format!(r#"{{
  "name": "test_profile",
  "proxy_addr": "127.0.0.1:{}",
  "handshake_timeout": "5s",
  "handshake_attempts": 3,
  "obfuscation": {{
    "jc": 0, "jmin": 0, "jmax": 0,
    "s1": 0, "s2": 0, "s3": 0, "s4": 0,
    "h1": "100-100", "h2": "200-200", "h3": "300-300", "h4": "400-400",
    "i1": "", "i2": "", "i3": "", "i4": "", "i5": "",
    "server_public_key": "",
    "server_private_key": "",
    "signature_validate": false,
    "encrypted_timestamp": false,
    "require_encrypted_timestamp": false
  }}
}}"#, proxy_port);

    let profile_path = PathBuf::from(&manifest_dir).join("test_profile_gen.json");
    std::fs::write(&profile_path, profile_content).expect("Failed to write profile");

    // 3. Start Proxy Server
    println!("Starting proxy-server...");
    let proxy_bin = target_dir.join("proxy-server");
    let proxy_child = Command::new(proxy_bin)
        .args(&[
            "--profile", profile_path.to_str().unwrap(),
            "--listen", &format!("127.0.0.1:{}", proxy_port)
        ])
        // .stdout(Stdio::inherit()) // Uncomment to see logs in test output (cargo test -- --nocapture)
        // .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start proxy-server");

    let _proxy_guard = ChildGuard { child: proxy_child, name: "proxy-server".into() };

    // Give it a moment to bind
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 4. Start Socks5d
    println!("Starting socks5d...");
    let socks_bin = target_dir.join("socks5d");
    let socks_child = Command::new(socks_bin)
        .args(&[
            "--profile", profile_path.to_str().unwrap(),
            "--listen", &format!("127.0.0.1:{}", socks_port)
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start socks5d");

    let _socks_guard = ChildGuard { child: socks_child, name: "socks5d".into() };

    tokio::time::sleep(Duration::from_secs(1)).await;

    // 5. Run Curl against external target (ifconfig.io) through SOCKS5
    println!("Running curl...");

    // Retry loop to account for "Listening" race or initial connect latency
    let mut success = false;
    for i in 0..3 {
        let start = std::time::Instant::now();
        let output = Command::new("curl")
            .args(&[
                "--socks5-hostname", &format!("127.0.0.1:{}", socks_port),
                "--connect-timeout", "10", // 10s connect timeout
                "--max-time", "15",        // 15s total timeout
                "http://ifconfig.io/country_code"
            ])
            .output()
            .expect("Failed to run curl");

        let duration = start.elapsed();
        println!("Curl #{} took {:?}", i, duration);

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Curl Output: {}", stdout);
            if stdout.trim() == "ES" || stdout.contains("ES") {
                success = true;
                break;
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("Curl failed (Status {:?}): stderr: {}", output.status.code(), stderr);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Cleanup profile
    let _ = std::fs::remove_file(profile_path);

    assert!(success, "Curl failed to retrieve country code ES via SOCKS5");
}
