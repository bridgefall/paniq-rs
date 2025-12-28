#![cfg(feature = "quic")]

use std::net::SocketAddr;
use std::task::{ready, Context, Poll};

use quinn::ClientConfig;
use thiserror::Error;
use tokio::io::Interest;
use tokio::net::UdpSocket;

use crate::envelope::client::{client_handshake, UdpPacketConn};
use crate::obf::{Framer, MessageType};
use quinn::udp::{RecvMeta, UdpState};
use quinn::{default_runtime, AsyncUdpSocket, Endpoint, EndpointConfig};
use rand::thread_rng;
use std::io;

#[derive(Debug, Error)]
pub enum QuicError {
    #[error("quic setup failed: {0}")]
    Setup(String),
    #[error("handshake failed: {0}")]
    Handshake(String),
}

pub async fn connect(
    socket: std::net::UdpSocket,
    server_addr: SocketAddr,
    framer: Framer,
    mut config: ClientConfig,
    initiation_payload: &[u8],
    server_name: &str,
) -> Result<(Endpoint, quinn::Connection), QuicError> {
    config
        .transport_config(std::sync::Arc::new({
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(quinn::VarInt::from_u32(30_000).into()));
            transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(1)));
            transport_config.initial_rtt(std::time::Duration::from_millis(10));
            transport_config
        }));

    let mut handshake_conn = UdpPacketConn::new(
        socket
            .try_clone()
            .map_err(|e| QuicError::Setup(e.to_string()))?,
        server_addr,
    )
    .map_err(|e| QuicError::Setup(e.to_string()))?;
    client_handshake(
        &mut handshake_conn,
        &framer,
        initiation_payload,
        &mut thread_rng(),
    )
    .map_err(|e| QuicError::Handshake(e.to_string()))?;

    connect_after_handshake(socket, server_addr, framer, config, server_name).await
}

pub async fn connect_after_handshake(
    socket: std::net::UdpSocket,
    server_addr: SocketAddr,
    framer: Framer,
    mut config: ClientConfig,
    server_name: &str,
) -> Result<(Endpoint, quinn::Connection), QuicError> {
    config
        .transport_config(std::sync::Arc::new({
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(quinn::VarInt::from_u32(30_000).into()));
            transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(1)));
            transport_config.initial_rtt(std::time::Duration::from_millis(10));
            transport_config
        }));

    let runtime = default_runtime().ok_or_else(|| QuicError::Setup("no async runtime".into()))?;
    let framed =
        FramedUdpSocket::new(socket, framer).map_err(|e| QuicError::Setup(e.to_string()))?;
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        framed,
        runtime.clone(),
    )
    .map_err(|e| QuicError::Setup(e.to_string()))?;
    let conn = endpoint
        .connect_with(config, server_addr, server_name)
        .map_err(|e| QuicError::Setup(e.to_string()))?
        .await
        .map_err(|e| QuicError::Setup(e.to_string()))?;

    Ok((endpoint, conn))
}

pub(crate) struct FramedUdpSocket {
    io: UdpSocket,
    framer: Framer,
}

impl FramedUdpSocket {
    pub(crate) fn new(sock: std::net::UdpSocket, framer: Framer) -> io::Result<Self> {
        sock.set_nonblocking(true)?;
        Ok(Self {
            io: UdpSocket::from_std(sock)?,
            framer,
        })
    }

    fn copy_payload(
        &self,
        payload: &[u8],
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> io::Result<usize> {
        let mut remaining = payload;
        let mut written = 0;
        for buf in bufs.iter_mut() {
            if remaining.is_empty() {
                break;
            }
            let count = remaining.len().min(buf.len());
            buf[..count].copy_from_slice(&remaining[..count]);
            remaining = &remaining[count..];
            written += count;
        }
        if !remaining.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "buffer too small"));
        }
        Ok(written)
    }
}

impl std::fmt::Debug for FramedUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedUdpSocket")
            .field("local", &self.io.local_addr().ok())
            .finish()
    }
}

impl AsyncUdpSocket for FramedUdpSocket {
    fn poll_send(
        &self,
        _state: &UdpState,
        cx: &mut Context,
        transmits: &[quinn::udp::Transmit],
    ) -> Poll<Result<usize, io::Error>> {
        let mut sent = 0;
        for transmit in transmits {
            let datagram = match self
                .framer
                .encode_frame(MessageType::Transport, &transmit.contents)
            {
                Ok(data) => data,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())))
                }
            };

            match self.io.poll_send_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if sent > 0 {
                        return Poll::Ready(Ok(sent));
                    } else {
                        return Poll::Pending;
                    }
                }
            }

            match self.io.try_io(Interest::WRITABLE, || {
                self.io.try_send_to(&datagram, transmit.destination)
            }) {
                Ok(_) => {
                    sent += 1;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if sent > 0 {
                        return Poll::Ready(Ok(sent));
                    } else {
                        return Poll::Pending;
                    }
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(sent))
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let mut backing = [0u8; 4096]; // Use stack-allocated buffer for common MTU
            match self
                .io
                .try_io(Interest::READABLE, || self.io.try_recv_from(&mut backing))
            {
                Ok((len, addr)) => {
                    match self.framer.decode_frame(&backing[..len]) {
                        Ok((msg, payload)) => {
                            if msg != MessageType::Transport {
                                continue;
                            }
                            let written = self.copy_payload(&payload, bufs)?;
                            meta[0] = RecvMeta {
                                addr,
                                len: written,
                                stride: written,
                                ecn: None,
                                dst_ip: None,
                            };
                            return Poll::Ready(Ok(1));
                        }
                        Err(e) => {
                            eprintln!("poll_recv: Decode error from {}: {}", addr, e);
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
