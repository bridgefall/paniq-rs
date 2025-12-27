#![cfg(feature = "socks5")]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use thiserror::Error;

const SOCKS_VER: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NO_ACCEPT: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCEEDED: u8 = 0x00;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

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
}

#[derive(Clone, Default)]
pub struct AuthConfig {
    pub users: HashMap<String, String>,
}

impl AuthConfig {
    pub fn requires_auth(&self) -> bool {
        !self.users.is_empty()
    }

    fn validate(&self, user: &str, pass: &str) -> bool {
        match self.users.get(user) {
            Some(expected) => expected == pass,
            None => false,
        }
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

    pub async fn serve_stream<S>(&self, mut stream: S) -> Result<(), SocksError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let method = self.negotiate_method(&mut stream).await?;
        if method == METHOD_USERPASS {
            self.handle_userpass(&mut stream).await?;
        }

        let target = self.read_request(&mut stream).await?;
        let mut remote = self.connector.connect(&target).await?;
        self.write_reply(&mut stream, REP_SUCCEEDED).await?;

        tokio::io::copy_bidirectional(&mut stream, &mut remote)
            .await
            .map_err(SocksError::Io)?;
        Ok(())
    }

    async fn negotiate_method<S>(&self, stream: &mut S) -> Result<u8, SocksError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        if header[0] != SOCKS_VER {
            return Err(SocksError::InvalidVersion(header[0]));
        }
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        let requires_auth = self.auth.requires_auth();
        let mut chosen = METHOD_NO_ACCEPT;
        if requires_auth {
            if methods.contains(&METHOD_USERPASS) {
                chosen = METHOD_USERPASS;
            }
        } else if methods.contains(&METHOD_NO_AUTH) {
            chosen = METHOD_NO_AUTH;
        }

        stream.write_all(&[SOCKS_VER, chosen]).await?;
        stream.flush().await?;
        if chosen == METHOD_NO_ACCEPT {
            return Err(SocksError::NoAcceptableMethod);
        }
        Ok(chosen)
    }

    async fn handle_userpass<S>(&self, stream: &mut S) -> Result<(), SocksError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x01 {
            stream.write_all(&[0x01, 0x01]).await?; // auth failure
            stream.flush().await?;
            return Err(SocksError::AuthFailed);
        }
        let ulen = header[1] as usize;
        let mut uname = vec![0u8; ulen];
        stream.read_exact(&mut uname).await?;
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await?;
        let mut pass = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut pass).await?;

        if self
            .auth
            .validate(&String::from_utf8_lossy(&uname), &String::from_utf8_lossy(&pass))
        {
            stream.write_all(&[0x01, 0x00]).await?;
            stream.flush().await?;
            Ok(())
        } else {
            stream.write_all(&[0x01, 0x01]).await?;
            stream.flush().await?;
            Err(SocksError::AuthFailed)
        }
    }

    async fn read_request<S>(&self, stream: &mut S) -> Result<TargetAddr, SocksError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[0] != SOCKS_VER {
            return Err(SocksError::InvalidVersion(header[0]));
        }
        if header[1] != CMD_CONNECT {
            self.write_reply(stream, REP_CMD_NOT_SUPPORTED).await?;
            return Err(SocksError::UnsupportedCommand(header[1]));
        }

        let target = match header[3] {
            ATYP_IPV4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                TargetAddr::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(addr)),
                    u16::from_be_bytes(port),
                ))
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut host = vec![0u8; len[0] as usize];
                stream.read_exact(&mut host).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                TargetAddr::Domain(
                    String::from_utf8_lossy(&host).into_owned(),
                    u16::from_be_bytes(port),
                )
            }
            ATYP_IPV6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                TargetAddr::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(addr)),
                    u16::from_be_bytes(port),
                ))
            }
            atyp => {
                self.write_reply(stream, REP_ADDR_NOT_SUPPORTED).await?;
                return Err(SocksError::UnsupportedAddress(atyp));
            }
        };
        Ok(target)
    }

    async fn write_reply<S>(&self, stream: &mut S, rep: u8) -> Result<(), SocksError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let resp = [
            SOCKS_VER,
            rep,
            0x00,
            ATYP_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        stream.write_all(&resp).await?;
        stream.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

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
            guard.pop().ok_or_else(|| SocksError::Connector("no stream".into()))
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

        client.write_all(&[SOCKS_VER, 1, METHOD_NO_AUTH]).await.unwrap();
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
            0x01,
            5,
            b'a',
            b'l',
            b'i',
            b'c',
            b'e',
            6,
            b's',
            b'e',
            b'c',
            b'r',
            b'e',
            b't',
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
        let server = Socks5Server::new(connector, AuthConfig::default());
        let (mut client, server_side) = duplex(64);

        let server_task = tokio::spawn(async move { server.serve_stream(server_side).await });
        client
            .write_all(&[SOCKS_VER, 1, METHOD_USERPASS])
            .await
            .unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [SOCKS_VER, METHOD_NO_ACCEPT]);
        assert!(server_task.await.unwrap().is_err());
    }
}
