use clap::Parser;
use paniq::config::{FileConfig, Socks5FileConfig};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use paniq::client::PaniqClient;
use paniq::control::ControlServer;
// use paniq::io::PaniqStream; // unused in this module
use paniq::kcp::client::ClientConfigWrapper;
use paniq::profile::Profile;
use paniq::proxy_protocol::{
    ADDR_TYPE_DOMAIN, ADDR_TYPE_IPV4, ADDR_TYPE_IPV6, PROTOCOL_VERSION, REPLY_SUCCESS,
};
use paniq::socks5::{AuthConfig, IoStream, RelayConnector, Socks5Server, SocksError, TargetAddr};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // Load daemon config if provided
    let daemon_config = if let Some(config_path) = &args.config {
        Socks5FileConfig::load_from_file(config_path)?
    } else {
        Socks5FileConfig::default()
    };

    // Initialize tracing with config log level
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(daemon_config.log_level_as_tracing().into())
                .from_env_lossy(),
        )
        .init();

    // CLI args override config file values
    let listen_addr = args
        .listen
        .clone()
        .unwrap_or_else(|| daemon_config.listen_addr.clone());
    let profile_path = args.profile.clone();

    let profile = Profile::from_file(&profile_path)?;
    let obf_config = profile.obf_config();

    // Determine server address from CLI args, config, or profile
    let proxy_addr_str = args
        .proxy_addr
        .clone()
        .or_else(|| {
            // No direct override in Socks5FileConfig to match Go,
            // but we could keep it if it's useful.
            // Go's ToServerConfig uses p.ProxyAddr.
            None
        })
        .unwrap_or_else(|| profile.proxy_addr.clone());
    let server_addr = proxy_addr_str.parse()?;

    // Map profile config to client config
    let kcp_profile = profile.kcp.clone().unwrap_or_default();
    let relay_buffer_size = profile.effective_kcp_max_payload();
    let config = ClientConfigWrapper {
        max_packet_size: profile.effective_kcp_max_packet_size(),
        max_payload: profile.effective_kcp_max_payload(),
        send_window: kcp_profile.send_window,
        recv_window: kcp_profile.recv_window,
        target_bps: kcp_profile.target_bps,
        rtt_ms: kcp_profile.rtt_ms,
        max_snd_queue: kcp_profile.max_snd_queue,
        transport_replay: profile.obfuscation.transport_replay,
        padding_policy: profile.transport_padding_policy(),
        handshake_timeout_secs: profile.handshake_timeout_or_default().as_secs(),
        handshake_attempts: profile.handshake_attempts,
        preamble_delay_ms: profile.preamble_delay_ms_or_default(),
    };

    let client = PaniqClient::new(server_addr, obf_config, config);
    let connector = PaniqConnector::new(client);

    let auth = args
        .auth_tuple()
        .map(|(user, pass)| {
            let mut users = std::collections::HashMap::new();
            users.insert(user, pass);
            AuthConfig { users }
        })
        .unwrap_or_default();

    let server = Arc::new(Socks5Server::new_with_relay_buffer(
        connector,
        auth,
        relay_buffer_size,
    ));
    let listener = TcpListener::bind(&listen_addr).await?;

    tracing::info!(listen_addr = %listen_addr, "SOCKS5 daemon listening");
    tracing::info!(server_addr = %server_addr, "Proxy server configured (connect on demand)");

    // Start control server if control socket is provided
    let control_socket: Option<PathBuf> = args.control_socket.clone().or_else(|| {
        // Try to get control socket from environment if not provided via CLI
        std::env::var("PANIQ_CONTROL_SOCKET")
            .ok()
            .map(PathBuf::from)
    });

    if let Some(control_socket) = &control_socket {
        let control_server = ControlServer::bind(control_socket)?;
        tracing::info!(socket = %control_socket.display(), "Control server listening");
        tokio::spawn(async move {
            if let Err(e) = control_server.run().await {
                tracing::error!(error = %e, "Control server error");
            }
        });
    }

    // Wait for shutdown signal
    tokio::select! {
        _ = async {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let server = server.clone();
                        tracing::debug!(client_addr = %addr, "Accepted client connection");
                        tokio::spawn(async move {
                            if let Err(err) = server.serve_stream(stream).await {
                                tracing::error!(error = %err, client_addr = %addr, "SOCKS5 stream error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Listener accept error");
                        return;
                    }
                }
            }
        } => {}
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal");
        }
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Paniq SOCKS5 daemon", long_about = None)]
struct Args {
    #[arg(short, long, help = "Path to daemon config JSON file")]
    config: Option<PathBuf>,

    #[arg(short, long, help = "Listen address (e.g. 127.0.0.1:1080)")]
    listen: Option<String>,

    #[arg(short, long, help = "Path to profile JSON file")]
    profile: PathBuf,

    #[arg(long, help = "Override proxy address from profile")]
    proxy_addr: Option<String>,

    #[arg(short, long, help = "Username for SOCKS5 authentication")]
    user: Option<String>,

    #[arg(short, long, help = "Password for SOCKS5 authentication")]
    auth: Option<String>,

    #[arg(long, help = "Path to control Unix domain socket")]
    control_socket: Option<PathBuf>,
}

impl Args {
    fn auth_tuple(&self) -> Option<(String, String)> {
        match (&self.user, &self.auth) {
            (Some(user), Some(auth)) => Some((user.clone(), auth.clone())),
            _ => None,
        }
    }
}

struct PaniqConnector {
    client: PaniqClient,
}

impl PaniqConnector {
    fn new(client: PaniqClient) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl RelayConnector for PaniqConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, SocksError> {
        let mut buf = Vec::new();
        buf.push(PROTOCOL_VERSION);

        let port = match target {
            TargetAddr::Ip(addr) => {
                match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        buf.push(ADDR_TYPE_IPV4);
                        buf.extend_from_slice(&ipv4.octets());
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        buf.push(ADDR_TYPE_IPV6);
                        buf.extend_from_slice(&ipv6.octets());
                    }
                }

                addr.port()
            }
            TargetAddr::Domain(host, port) => {
                buf.push(ADDR_TYPE_DOMAIN);
                buf.push(host.len() as u8);
                buf.extend_from_slice(host.as_bytes());
                *port
            }
        };

        buf.extend_from_slice(&port.to_be_bytes());

        let mut stream = self
            .client
            .open_stream()
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;

        // Perform proxy protocol handshake
        stream
            .write_all(&buf)
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;

        let mut reply = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut reply)
            .await
            .map_err(|e| SocksError::Connector(format!("handshake read failed: {}", e)))?;

        if reply[0] != REPLY_SUCCESS {
            return Err(SocksError::Connector(format!(
                "proxy rejected request: {}",
                reply[0]
            )));
        }

        Ok(Box::new(stream))
    }
}
