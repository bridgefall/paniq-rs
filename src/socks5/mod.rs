#![cfg(feature = "socks5")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use fast_socks5::consts::{
    SOCKS5_ADDR_TYPE_IPV4, SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
    SOCKS5_REPLY_COMMAND_NOT_SUPPORTED, SOCKS5_REPLY_SUCCEEDED, SOCKS5_VERSION,
};
use fast_socks5::server::{
    AcceptAuthentication, Authentication, Config as FastConfig, Socks5Socket,
};
use fast_socks5::util::target_addr as fast_target;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use thiserror::Error;

#[allow(dead_code)]
const REP_CMD_NOT_SUPPORTED: u8 = SOCKS5_REPLY_COMMAND_NOT_SUPPORTED;
#[allow(dead_code)]
const REP_ADDR_NOT_SUPPORTED: u8 = SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED;

pub trait IoStream: AsyncRead + AsyncWrite + Unpin {}

impl<T: AsyncRead + AsyncWrite + Unpin> IoStream for T {}

type BoxedStream = Box<dyn IoStream + Send>;

#[derive(Debug, Error)]
pub enum SocksError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid socks version {0}")]
    InvalidVersion(u8),
    #[error("no acceptable auth methods")]
    NoAcceptableMethod,
    #[error("authentication failed")]
    AuthFailed,
    #[error("unsupported command {0}")]
    UnsupportedCommand(u8),
    #[error("unsupported address type {0}")]
    UnsupportedAddress(u8),
    #[error("connector error: {0}")]
    Connector(String),
    #[error("socks5 protocol error: {0}")]
    Protocol(String),
}

#[derive(Clone, Default)]
pub struct AuthConfig {
    pub users: HashMap<String, String>,
}

impl AuthConfig {
    pub fn requires_auth(&self) -> bool {
        !self.users.is_empty()
    }
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[async_trait]
pub trait RelayConnector: Send + Sync {
    async fn connect(&self, target: &TargetAddr) -> Result<BoxedStream, SocksError>;
}

pub struct TcpConnector;

#[async_trait]
impl RelayConnector for TcpConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<BoxedStream, SocksError> {
        let addr = match target {
            TargetAddr::Ip(addr) => *addr,
            TargetAddr::Domain(host, port) => {
                let mut addrs = tokio::net::lookup_host((host.as_str(), *port))
                    .await
                    .map_err(SocksError::Io)?;
                addrs
                    .next()
                    .ok_or_else(|| SocksError::Connector("no resolved addresses".into()))?
            }
        };
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;
        Ok(Box::new(stream))
    }
}

pub struct Socks5Server<C> {
    connector: Arc<C>,
    auth: AuthConfig,
}

impl<C: RelayConnector> Socks5Server<C> {
    pub fn new(connector: C, auth: AuthConfig) -> Self {
        Self {
            connector: Arc::new(connector),
            auth,
        }
    }

    pub async fn serve_stream<S>(&self, stream: S) -> Result<(), SocksError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.auth.requires_auth() {
            let config = build_auth_config(&self.auth)?;
            self.serve_with_config(stream, config).await
        } else {
            let config = build_noauth_config();
            self.serve_with_config(stream, config).await
        }
    }

    async fn serve_with_config<S, A>(
        &self,
        stream: S,
        config: FastConfig<A>,
    ) -> Result<(), SocksError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        A: Authentication + Send + Sync + 'static,
        A::Item: Send,
    {
        let socket = Socks5Socket::new(stream, Arc::new(config));

        tracing::info!("Upgrading to SOCKS5 protocol");
        let mut socket = socket
            .upgrade_to_socks5()
            .await
            .map_err(|e| SocksError::Protocol(e.to_string()))?;

        let target = map_target(socket.target_addr().cloned())?;
        tracing::debug!(target = ?target, "Connecting to target");
        let remote = self.connector.connect(&target).await?;
        tracing::info!("Connected to target, sending success reply");

        send_success_reply(&mut socket, &target).await?;
        tracing::info!("Success reply sent, starting relay");

        relay_bidirectional(socket, remote).await
    }
}

#[derive(Clone)]
struct MapAuth {
    users: HashMap<String, String>,
}

#[async_trait]
impl Authentication for MapAuth {
    type Item = ();

    async fn authenticate(&self, credentials: Option<(String, String)>) -> Option<Self::Item> {
        let (user, pass) = credentials?;
        self.users
            .get(&user)
            .filter(|expected| *expected == &pass)
            .map(|_| ())
    }
}

fn build_auth_config(auth: &AuthConfig) -> Result<FastConfig<MapAuth>, SocksError> {
    let mut config = FastConfig::<MapAuth>::default();
    config.set_execute_command(false);
    config.set_dns_resolve(false);
    config.set_allow_no_auth(false);

    Ok(config.with_authentication(MapAuth {
        users: auth.users.clone(),
    }))
}

fn build_noauth_config() -> FastConfig<AcceptAuthentication> {
    let mut config = FastConfig::<AcceptAuthentication>::default();
    config.set_execute_command(false);
    config.set_dns_resolve(false);
    config.set_allow_no_auth(true);
    config
}

fn map_target(addr: Option<fast_target::TargetAddr>) -> Result<TargetAddr, SocksError> {
    match addr {
        Some(fast_target::TargetAddr::Ip(ip)) => Ok(TargetAddr::Ip(ip)),
        Some(fast_target::TargetAddr::Domain(domain, port)) => Ok(TargetAddr::Domain(domain, port)),
        None => Err(SocksError::Protocol("missing target address".into())),
    }
}

async fn send_success_reply<S>(stream: &mut S, target: &TargetAddr) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut resp = Vec::with_capacity(22);
    resp.push(SOCKS5_VERSION);
    resp.push(SOCKS5_REPLY_SUCCEEDED);
    resp.push(0x00); // reserved

    // Send the actual target address back to client
    match target {
        TargetAddr::Ip(addr) => match addr {
            std::net::SocketAddr::V4(v4) => {
                resp.push(SOCKS5_ADDR_TYPE_IPV4);
                resp.extend_from_slice(&v4.ip().octets());
                resp.extend_from_slice(&v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                resp.push(fast_socks5::consts::SOCKS5_ADDR_TYPE_IPV6);
                resp.extend_from_slice(&v6.ip().octets());
                resp.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
        TargetAddr::Domain(domain, port) => {
            resp.push(fast_socks5::consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME);
            resp.push(domain.len() as u8);
            resp.extend_from_slice(domain.as_bytes());
            resp.extend_from_slice(&port.to_be_bytes());
        }
    }

    stream.write_all(&resp).await?;
    stream.flush().await?;
    Ok(())
}

async fn relay_bidirectional<C, R>(client: C, remote: R) -> Result<(), SocksError>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tracing::info!("Starting bidirectional relay");
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let client_to_remote = async {
        tracing::debug!("client_to_remote: Starting");
        let mut buf = vec![0u8; 8192];
        let mut total = 0u64;
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => {
                    tracing::debug!(
                        bytes_out = total,
                        "client_to_remote: Got EOF from client"
                    );
                    break;
                }
                Ok(n) => {
                    tracing::trace!(
                        bytes = n,
                        direction = "client_to_remote",
                        "Read from client"
                    );
                    remote_write.write_all(&buf[..n]).await?;
                    total += n as u64;
                }
                Err(e) => {
                    tracing::error!(error = %e, "client_to_remote: Read error");
                    return Err(e);
                }
            }
        }
        // Send FIN frame to signal graceful shutdown of the KCP/smux stream.
        // This is critical for smux stream cleanup; without it, the session
        // state becomes corrupted when opening subsequent streams.
        tracing::debug!("client_to_remote: Shutting down remote write");
        if let Err(e) = remote_write.shutdown().await {
            tracing::warn!(error = %e, "client_to_remote: Shutdown failed, stream may not be cleanly closed");
        }
        tracing::debug!("client_to_remote: Complete");
        Ok::<u64, std::io::Error>(total)
    };

    let remote_to_client = async {
        tracing::debug!("remote_to_client: Starting");
        let mut buf = vec![0u8; 8192];
        let mut total = 0u64;
        loop {
            match remote_read.read(&mut buf).await {
                Ok(0) => {
                    tracing::debug!(
                        bytes_in = total,
                        "remote_to_client: Got EOF from remote (KCP)"
                    );
                    break;
                }
                Ok(n) => {
                    tracing::trace!(
                        bytes = n,
                        direction = "remote_to_client",
                        "Read from KCP"
                    );
                    client_write.write_all(&buf[..n]).await?;
                    total += n as u64;
                }
                Err(e) => {
                    tracing::error!(error = %e, "remote_to_client: Read error");
                    return Err(e);
                }
            }
        }
        // Shutdown the client write half for clean TCP closure
        tracing::debug!("remote_to_client: Shutting down client write");
        if let Err(e) = client_write.shutdown().await {
            tracing::warn!(error = %e, "remote_to_client: Shutdown failed");
        }
        Ok::<u64, std::io::Error>(total)
    };

    tracing::debug!("Launching both relay tasks");
    let result = tokio::try_join!(client_to_remote, remote_to_client);

    match result {
        Ok((to_remote, to_client)) => {
            tracing::info!(
                bytes_out = to_remote,
                bytes_in = to_client,
                "Relay complete"
            );
            Ok(())
        }
        Err(e) => {
            tracing::error!(error = %e, "Relay error");
            Err(SocksError::Io(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    const SOCKS_VER: u8 = SOCKS5_VERSION;
    const METHOD_NO_AUTH: u8 = fast_socks5::consts::SOCKS5_AUTH_METHOD_NONE;
    const METHOD_USERPASS: u8 = fast_socks5::consts::SOCKS5_AUTH_METHOD_PASSWORD;
    const METHOD_NO_ACCEPT: u8 = fast_socks5::consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE;
    const CMD_CONNECT: u8 = fast_socks5::consts::SOCKS5_CMD_TCP_CONNECT;
    const ATYP_IPV4: u8 = SOCKS5_ADDR_TYPE_IPV4;
    const REP_SUCCEEDED: u8 = SOCKS5_REPLY_SUCCEEDED;

    #[derive(Clone)]
    struct TestConnector {
        streams: Arc<tokio::sync::Mutex<Vec<BoxedStream>>>,
    }

    impl TestConnector {
        fn new(streams: Vec<BoxedStream>) -> Self {
            Self {
                streams: Arc::new(tokio::sync::Mutex::new(streams)),
            }
        }
    }

    #[async_trait]
    impl RelayConnector for TestConnector {
        async fn connect(&self, _target: &TargetAddr) -> Result<BoxedStream, SocksError> {
            let mut guard = self.streams.lock().await;
            guard
                .pop()
                .ok_or_else(|| SocksError::Connector("no stream".into()))
        }
    }

    fn ipv4_req(port: u16) -> Vec<u8> {
        let mut req = vec![SOCKS_VER, CMD_CONNECT, 0x00, ATYP_IPV4, 127, 0, 0, 1];
        req.extend_from_slice(&port.to_be_bytes());
        req
    }

    async fn drive_no_auth(server: Socks5Server<TestConnector>) {
        let (mut client, server_side) = duplex(1024);
        let (remote_client, mut remote_server) = duplex(1024);

        let connector = server.connector.clone();
        connector
            .streams
            .lock()
            .await
            .push(Box::new(remote_client) as BoxedStream);

        let server_task = tokio::spawn(async move { server.serve_stream(server_side).await });

        client
            .write_all(&[SOCKS_VER, 1, METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut method_resp = [0u8; 2];
        client.read_exact(&mut method_resp).await.unwrap();
        assert_eq!(method_resp, [SOCKS_VER, METHOD_NO_AUTH]);

        client.write_all(&ipv4_req(8080)).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], REP_SUCCEEDED);

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        remote_server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        remote_server.write_all(b"pong").await.unwrap();
        let mut back = [0u8; 4];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");

        drop(client);
        drop(remote_server);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn socks5_no_auth_roundtrip() {
        let connector = TestConnector::new(Vec::new());
        let server = Socks5Server::new(connector, AuthConfig::default());
        drive_no_auth(server).await;
    }

    #[tokio::test]
    async fn socks5_userpass_success() {
        let connector = TestConnector::new(Vec::new());
        let mut users = HashMap::new();
        users.insert("alice".to_string(), "secret".to_string());
        let server = Socks5Server::new(connector, AuthConfig { users });

        let (mut client, server_side) = duplex(1024);
        let (remote_client, mut remote_server) = duplex(1024);
        server
            .connector
            .streams
            .lock()
            .await
            .push(Box::new(remote_client) as BoxedStream);

        let server_task = tokio::spawn(async move { server.serve_stream(server_side).await });

        client
            .write_all(&[SOCKS_VER, 2, METHOD_USERPASS, METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut method_resp = [0u8; 2];
        client.read_exact(&mut method_resp).await.unwrap();
        assert_eq!(method_resp, [SOCKS_VER, METHOD_USERPASS]);

        let auth = [
            0x01, 5, b'a', b'l', b'i', b'c', b'e', 6, b's', b'e', b'c', b'r', b'e', b't',
        ];
        client.write_all(&auth).await.unwrap();
        let mut auth_resp = [0u8; 2];
        client.read_exact(&mut auth_resp).await.unwrap();
        assert_eq!(auth_resp, [0x01, 0x00]);

        client.write_all(&ipv4_req(9090)).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], REP_SUCCEEDED);

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        remote_server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        remote_server.write_all(b"pong").await.unwrap();
        let mut back = [0u8; 4];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");

        drop(client);
        drop(remote_server);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn socks5_rejects_bad_method() {
        let connector = TestConnector::new(Vec::new());
        let mut users = HashMap::new();
        users.insert("bob".to_string(), "hunter2".to_string());
        let server = Socks5Server::new(connector, AuthConfig { users });
        let (mut client, server_side) = duplex(64);

        let server_task = tokio::spawn(async move { server.serve_stream(server_side).await });
        client
            .write_all(&[SOCKS_VER, 1, METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [SOCKS_VER, METHOD_NO_ACCEPT]);
        assert!(server_task.await.unwrap().is_err());
    }
}
