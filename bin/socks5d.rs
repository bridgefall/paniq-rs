use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use paniq::client::PaniqClient;
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
    // Initialize tracing subscriber with environment filter
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = parse_args()?;
    let profile = Profile::from_file(&args.profile)?;
    let obf_config = profile.obf_config();

    let server_addr = args
        .proxy_addr_override
        .as_deref()
        .unwrap_or(&profile.proxy_addr)
        .parse()?;

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
        .auth
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
    let listener = TcpListener::bind(&args.listen_addr).await?;

    tracing::info!(listen_addr = %args.listen_addr, "SOCKS5 daemon listening");
    tracing::info!(server_addr = %server_addr, "Proxy server configured (connect on demand)");

    loop {
        let (stream, addr) = listener.accept().await?;
        let server = server.clone();
        tracing::debug!(client_addr = %addr, "Accepted client connection");
        tokio::spawn(async move {
            if let Err(err) = server.serve_stream(stream).await {
                tracing::error!(error = %err, client_addr = %addr, "SOCKS5 stream error");
            }
        });
    }
}

struct Args {
    listen_addr: String,
    profile: PathBuf,
    proxy_addr_override: Option<String>,
    auth: Option<(String, String)>,
}

fn parse_args() -> Result<Args, pico_args::Error> {
    let mut pargs = pico_args::Arguments::from_env();
    let listen_addr = pargs.value_from_str(["-l", "--listen"])?;
    let profile: PathBuf = pargs.value_from_str(["-p", "--profile"])?;
    let proxy_addr_override = pargs.opt_value_from_str("--proxy-addr")?;
    let auth = if let (Ok(user), Ok(pass)) = (
        pargs.value_from_str(["-u", "--user"]),
        pargs.value_from_str(["-a", "--auth"]),
    ) {
        Some((user, pass))
    } else {
        None
    };
    Ok(Args {
        listen_addr,
        profile,
        proxy_addr_override,
        auth,
    })
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
