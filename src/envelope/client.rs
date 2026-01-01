use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, Weak};
use std::thread::sleep;
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::envelope::EnvelopeError;
use crate::obf::{Framer, MessageType};

pub trait PacketConn {
    fn send(&mut self, data: Vec<u8>) -> Result<(), EnvelopeError>;
    fn recv(&mut self) -> Result<Vec<u8>, EnvelopeError>;
}

/// Async version of PacketConn for tokio sockets.
/// This allows using tokio UdpSocket directly without from_std() conversion.
#[cfg(feature = "kcp")]
pub trait AsyncPacketConn {
    async fn send(&mut self, data: Vec<u8>) -> Result<(), EnvelopeError>;
    async fn recv(&mut self) -> Result<Vec<u8>, EnvelopeError>;
}

#[derive(Clone, Default)]
pub struct InMemoryConn {
    inbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    peer: Weak<Mutex<VecDeque<Vec<u8>>>>,
}

impl InMemoryConn {
    pub fn pair() -> (Self, Self) {
        let a = Arc::new(Mutex::new(VecDeque::new()));
        let b = Arc::new(Mutex::new(VecDeque::new()));
        let c1 = InMemoryConn {
            inbox: a.clone(),
            peer: Arc::downgrade(&b),
        };
        let c2 = InMemoryConn {
            inbox: b,
            peer: Arc::downgrade(&a),
        };
        (c1, c2)
    }
}

/// UDP-backed packet connection for real sockets.
pub struct UdpPacketConn {
    sock: UdpSocket,
    peer: SocketAddr,
}

impl UdpPacketConn {
    pub fn new(sock: UdpSocket, peer: SocketAddr) -> std::io::Result<Self> {
        sock.connect(peer)?;
        sock.set_nonblocking(true)?;
        Ok(Self { sock, peer })
    }
}

impl PacketConn for InMemoryConn {
    fn send(&mut self, data: Vec<u8>) -> Result<(), EnvelopeError> {
        if let Some(peer) = self.peer.upgrade() {
            peer.lock().unwrap().push_back(data);
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, EnvelopeError> {
        loop {
            if let Some(data) = self.inbox.lock().unwrap().pop_front() {
                return Ok(data);
            }
            sleep(Duration::from_millis(1));
        }
    }
}

impl PacketConn for UdpPacketConn {
    fn send(&mut self, data: Vec<u8>) -> Result<(), EnvelopeError> {
        self.sock
            .send(&data)
            .map(|_| ())
            .map_err(|_| EnvelopeError::HandshakeTimeout)
    }

    fn recv(&mut self) -> Result<Vec<u8>, EnvelopeError> {
        let mut buf = vec![0u8; 65536];
        let start = Instant::now();
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((len, addr)) if addr == self.peer => return Ok(buf[..len].to_vec()),
                Ok(_) => continue,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    sleep(Duration::from_millis(1));
                }
                Err(_) => return Err(EnvelopeError::HandshakeTimeout),
            }
            if start.elapsed() > Duration::from_secs(5) {
                return Err(EnvelopeError::HandshakeTimeout);
            }
        }
    }
}

pub struct ClientConn<C: PacketConn> {
    inner: C,
}

impl<C: PacketConn> ClientConn<C> {
    pub fn new(inner: C) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> C {
        self.inner
    }
}

pub fn client_handshake<R: RngCore, C: PacketConn>(
    conn: &mut C,
    framer: &Framer,
    initiation_payload: &[u8],
    _rng: &mut R,
) -> Result<Vec<u8>, EnvelopeError> {
    const MAX_ATTEMPTS: usize = 64;
    const PACE: Duration = Duration::from_millis(2);

    for junk in framer
        .junk_datagrams()
        .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?
    {
        conn.send(junk)?;
        sleep(PACE);
    }
    for sig in framer
        .signature_datagrams()
        .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?
    {
        conn.send(sig)?;
        sleep(PACE);
    }
    let init = framer
        .encode_frame(MessageType::Initiation, initiation_payload)
        .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?;
    conn.send(init)?;

    for _ in 0..MAX_ATTEMPTS {
        let datagram = conn.recv()?;
        if let Ok((msg, payload)) = framer.decode_frame(&datagram) {
            if msg == MessageType::Response {
                return Ok(payload);
            }
        }
    }
    Err(EnvelopeError::HandshakeTimeout)
}

/// Async version of client_handshake for tokio sockets.
#[cfg(feature = "kcp")]
pub async fn client_handshake_async<R: RngCore, C: AsyncPacketConn>(
    conn: &mut C,
    framer: &Framer,
    initiation_payload: &[u8],
    _rng: &mut R,
) -> Result<Vec<u8>, EnvelopeError> {
    const MAX_ATTEMPTS: usize = 64;
    const PACE: Duration = Duration::from_millis(2);

    for junk in framer
        .junk_datagrams()
        .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?
    {
        conn.send(junk).await?;
        tokio::time::sleep(PACE).await;
    }
    for sig in framer
        .signature_datagrams()
        .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?
    {
        conn.send(sig).await?;
        tokio::time::sleep(PACE).await;
    }
    let init = framer
        .encode_frame(MessageType::Initiation, initiation_payload)
        .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?;
    conn.send(init).await?;

    for _ in 0..MAX_ATTEMPTS {
        let datagram = conn.recv().await?;
        if let Ok((msg, payload)) = framer.decode_frame(&datagram) {
            if msg == MessageType::Response {
                return Ok(payload);
            }
        }
    }
    Err(EnvelopeError::HandshakeTimeout)
}

/// Tokio-backed async packet connection.
#[cfg(feature = "kcp")]
pub struct TokioPacketConn {
    pub sock: tokio::net::UdpSocket,
    peer: SocketAddr,
}

#[cfg(feature = "kcp")]
impl TokioPacketConn {
    /// Create a new TokioPacketConn connected to the specified peer.
    pub fn new(sock: tokio::net::UdpSocket, peer: SocketAddr) -> Self {
        Self { sock, peer }
    }

    /// Create from a bound tokio UdpSocket and peer address.
    pub async fn bound(sock: tokio::net::UdpSocket, peer: SocketAddr) -> std::io::Result<Self> {
        sock.connect(peer).await?;
        Ok(Self { sock, peer })
    }
}

#[cfg(feature = "kcp")]
impl AsyncPacketConn for TokioPacketConn {
    async fn send(&mut self, data: Vec<u8>) -> Result<(), EnvelopeError> {
        self.sock
            .send(&data)
            .await
            .map(|_| ())
            .map_err(|_| EnvelopeError::HandshakeTimeout)
    }

    async fn recv(&mut self) -> Result<Vec<u8>, EnvelopeError> {
        let mut buf = vec![0u8; 65536];
        let timeout = Duration::from_secs(5);

        match tokio::time::timeout(timeout, self.sock.recv(&mut buf)).await {
            Ok(Ok(len)) => Ok(buf[..len].to_vec()),
            Ok(Err(_e)) => Err(EnvelopeError::HandshakeTimeout),
            Err(_) => Err(EnvelopeError::HandshakeTimeout),
        }
    }
}
