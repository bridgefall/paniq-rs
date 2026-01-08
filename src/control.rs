//! Control plane for SOCKS5 server.
//!
//! Provides observability via Unix domain socket with Ping and GetStats commands.

use crate::telemetry::TransportSnapshot;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;
use tokio::net::UnixListener;

/// Control request sent by clients.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlRequest {
    Ping,
    GetStats,
}

/// Control response sent by the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlResponse {
    Pong,
    Stats(TransportSnapshot),
    Error(String),
}

/// Control server that handles observability requests.
pub struct ControlServer {
    listener: UnixListener,
}

impl ControlServer {
    /// Bind a new control server to the given socket path.
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref();
        // Remove stale socket if it exists
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        Ok(Self { listener })
    }

    /// Run the control server, handling incoming requests.
    pub async fn run(&self) -> io::Result<()> {
        loop {
            match self.accept().await {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "Control server accept error");
                }
            }
        }
    }

    async fn accept(&self) -> io::Result<()> {
        let (mut stream, _addr) = self.listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = match stream.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(error = %e, "Control request read error");
                    return;
                }
            };

            let request: ControlRequest = match serde_json::from_slice(&buf[..n]) {
                Ok(req) => req,
                Err(e) => {
                    tracing::warn!(error = %e, "Control request deserialize error");
                    let response = ControlResponse::Error(format!("Invalid request: {}", e));
                    let _ = send_response(&mut stream, &response).await;
                    return;
                }
            };

            let response = match request {
                ControlRequest::Ping => ControlResponse::Pong,
                ControlRequest::GetStats => {
                    ControlResponse::Stats(crate::telemetry::transport_snapshot())
                }
            };

            if let Err(e) = send_response(&mut stream, &response).await {
                tracing::warn!(error = %e, "Control response write error");
            }
        });
        Ok(())
    }
}

async fn send_response(
    stream: &mut tokio::net::UnixStream,
    response: &ControlResponse,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(response).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Serialization failed: {}", e),
        )
    })?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;
    Ok(())
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_request_serialization() {
        let req = ControlRequest::Ping;
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: ControlRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, ControlRequest::Ping));

        let req = ControlRequest::GetStats;
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: ControlRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, ControlRequest::GetStats));
    }

    #[test]
    fn test_control_response_serialization() {
        let resp = ControlResponse::Pong;
        let bytes = serde_json::to_vec(&resp).unwrap();
        let decoded: ControlResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, ControlResponse::Pong));

        let stats = TransportSnapshot::default();
        let resp = ControlResponse::Stats(stats);
        let bytes = serde_json::to_vec(&resp).unwrap();
        let decoded: ControlResponse = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            ControlResponse::Stats(s) => {
                assert_eq!(s.active_connections, 0);
            }
            _ => panic!("Expected Stats response"),
        };

        let resp = ControlResponse::Error("test error".to_string());
        let bytes = serde_json::to_vec(&resp).unwrap();
        let decoded: ControlResponse = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            ControlResponse::Error(e) => {
                assert_eq!(e, "test error");
            }
            _ => panic!("Expected Error response"),
        };
    }

    #[tokio::test]
    async fn test_control_server_ping() {
        let temp_socket = tempfile::NamedTempFile::new().unwrap();
        let socket_path = temp_socket.path().with_extension("sock");
        let server = ControlServer::bind(&socket_path).unwrap();

        // Spawn server in background
        tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Connect and send ping
        let mut stream = tokio::net::UnixStream::connect(&socket_path).await.unwrap();

        let req = ControlRequest::Ping;
        let bytes = serde_json::to_vec(&req).unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response: ControlResponse = serde_json::from_slice(&buf).unwrap();
        assert!(matches!(response, ControlResponse::Pong));
    }

    #[tokio::test]
    async fn test_control_server_stats() {
        let temp_socket = tempfile::NamedTempFile::new().unwrap();
        let socket_path = temp_socket.path().with_extension("sock_stats");
        let server = ControlServer::bind(&socket_path).unwrap();

        // Increment some stats
        crate::telemetry::record_connection_open();
        crate::telemetry::record_udp_in(100);

        // Spawn server in background
        tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Connect and send GetStats
        let mut stream = tokio::net::UnixStream::connect(&socket_path).await.unwrap();

        let req = ControlRequest::GetStats;
        let bytes = serde_json::to_vec(&req).unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response: ControlResponse = serde_json::from_slice(&buf).unwrap();
        match response {
            ControlResponse::Stats(stats) => {
                assert!(stats.active_connections >= 1);
                assert!(stats.udp_in_bytes >= 100);
            }
            _ => panic!("Expected Stats response, got {:?}", response),
        }
    }
}
