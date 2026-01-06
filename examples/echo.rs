//! Simple Echo Example using Paniq SDK
//!
//! This example demonstrates how to build a custom server and client using paniq-rs.
//! It bypasses the SOCKS5/proxy protocol entirely, treating paniq as a generic
//! encrypted/obfuscated transport layer.
//!
//! To run:
//! cargo run --example echo --features "kcp socks5" -- [path/to/profile.json]

use paniq::client::PaniqClient;
use paniq::kcp::client::ClientConfigWrapper;
use paniq::kcp::server::{listen, ServerConfigWrapper};
use paniq::obf::{Config as ObfConfig, Framer};
use paniq::profile::Profile;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing with environment filter
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // 1. Setup Shared Configuration (Obfuscation keys)
    // Parse command line arguments for profile path
    let args: Vec<String> = std::env::args().collect();
    let profile_path = if args.len() > 1 {
        &args[1]
    } else {
        "examples/profile.json"
    };

    println!("Loading profile from: {}", profile_path);
    let profile = Profile::from_file(profile_path)?;
    let obf_config = profile.obf_config();

    // 2. Start the Echo Server
    let server_addr = start_echo_server(obf_config.clone()).await?;
    println!("Echo server listening on {}", server_addr);

    // 3. Run the Client
    run_echo_client(server_addr, obf_config).await?;

    Ok(())
}

/// Starts a simple server that echoes back everything it receives.
async fn start_echo_server(
    obf_config: ObfConfig,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    let framer = Framer::new(obf_config)?;
    let config = ServerConfigWrapper::default();

    // Bind to port 0 to get an ephemeral port
    let listen_addr: SocketAddr = "127.0.0.1:0".parse()?;

    let endpoint = listen(listen_addr, framer, config).await?;
    let local_addr = endpoint.local_addr();

    // Spawn server loop
    tokio::spawn(async move {
        println!("[Server] Ready to accept connections");
        while let Some(conn) = endpoint.accept().await {
            let peer = conn.peer_addr();
            println!("[Server] Accepted connection from {}", peer);

            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn).await {
                    eprintln!("[Server] Connection error: {}", e);
                }
            });
        }
    });

    Ok(local_addr)
}

async fn handle_connection(
    conn: paniq::kcp::server::IncomingConnection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut server_conn = conn.await_connection().await?;

    while let Ok((mut send, mut recv)) = server_conn.accept_bi().await {
        println!("[Server] Accepted new stream");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            loop {
                match recv.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        println!("[Server] Received {} bytes: {:?}", n, &buf[..n]);
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            eprintln!("[Server] Write error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[Server] Read error: {}", e);
                        break;
                    }
                }
            }
            println!("[Server] Stream closed");
        });
    }
    Ok(())
}

async fn run_echo_client(
    server_addr: SocketAddr,
    obf_config: ObfConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Configure client options (defaults are usually fine)
    let client_config = ClientConfigWrapper::default();

    let client = PaniqClient::new(server_addr, obf_config, client_config);

    println!("[Client] Opening stream...");
    let mut stream = client.open_stream().await?;

    let message = b"Hello from Paniq SDK!";
    println!("[Client] Sending: {:?}", String::from_utf8_lossy(message));
    stream.write_all(message).await?;

    // Read response
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await?;
    println!(
        "[Client] Received: {:?}",
        String::from_utf8_lossy(&buf[..n])
    );

    assert_eq!(&buf[..n], message);
    println!("[Client] Echo verified!");

    Ok(())
}
