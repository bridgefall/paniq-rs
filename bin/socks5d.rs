use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use paniq::kcp::client::connect;
use paniq::kcp::client::ClientConfigWrapper;
use paniq::obf::Framer;
use paniq::profile::Profile;
use paniq::socks5::{AuthConfig, IoStream, RelayConnector, Socks5Server, SocksError, TargetAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = parse_args()?;
    let profile = Profile::from_file(&args.profile)?;
    let obf_config = profile.obf_config();
    let framer = Framer::new(obf_config.clone()).expect("framer");

    let server_addr = profile.proxy_addr.parse()?;

    // Map profile config to client config
    let config = ClientConfigWrapper {
        max_packet_size: profile.kcp.as_ref().map(|k| k.max_packet_size).unwrap_or(1350),
        max_payload: profile.kcp.as_ref().map(|k| k.max_payload).unwrap_or(1200),
        transport_replay: profile.obfuscation.transport_replay,
        handshake_timeout_secs: 5,
        handshake_attempts: 3,
        preamble_delay_ms: 5,
    };

    let (_ep, conn) = connect(
        std::net::UdpSocket::bind("0.0.0.0:0")?,
        server_addr,
        framer,
        config,
        &[],
        "paniq",
    )
    .await?;

    let connector = KcpConnector { conn };

    let auth = args
        .auth
        .map(|(user, pass)| {
            let mut users = std::collections::HashMap::new();
            users.insert(user, pass);
            AuthConfig { users }
        })
        .unwrap_or_default();

    let server = Arc::new(Socks5Server::new(connector, auth));
    let listener = TcpListener::bind(&args.listen_addr).await?;

    eprintln!("SOCKS5 daemon listening on {}", args.listen_addr);
    eprintln!("Connected to proxy server at {}", server_addr);

    loop {
        let (stream, addr) = listener.accept().await?;
        let server = server.clone();
        eprintln!("accepted {addr}");
        tokio::spawn(async move {
            if let Err(err) = server.serve_stream(stream).await {
                eprintln!("socks5 stream error: {err}");
            }
        });
    }
}

struct Args {
    listen_addr: String,
    profile: PathBuf,
    auth: Option<(String, String)>,
}

fn parse_args() -> Result<Args, pico_args::Error> {
    let mut pargs = pico_args::Arguments::from_env();
    let listen_addr = pargs.value_from_str(["-l", "--listen"])?;
    let profile: PathBuf = pargs.value_from_str(["-p", "--profile"])?;
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
        auth,
    })
}

struct KcpConnector {
    conn: paniq::kcp::client::Connection,
}

#[async_trait::async_trait]
impl RelayConnector for KcpConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, SocksError> {
        let mut buf = Vec::new();
        buf.push(0x01); // protocol version

        let port = match target {
            TargetAddr::Ip(addr) => {
                match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        buf.push(0x01); // IPv4
                        buf.extend_from_slice(&ipv4.octets());
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        buf.push(0x04); // IPv6
                        buf.extend_from_slice(&ipv6.octets());
                    }
                }

                addr.port()
            }
            TargetAddr::Domain(host, port) => {
                buf.push(0x03); // Domain
                buf.push(host.len() as u8);
                buf.extend_from_slice(host.as_bytes());
                *port
            }
        };

        buf.extend_from_slice(&port.to_be_bytes());

        let (mut send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;
        send.write_all(&buf)
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;
        Ok(Box::new(StreamWrapper { send, recv }))
    }
}

struct StreamWrapper {
    send: paniq::kcp::client::SendStream,
    recv: paniq::kcp::client::RecvStream,
}

impl AsyncRead for StreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for StreamWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_shutdown(cx)
    }
}
