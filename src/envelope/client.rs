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
) -> Result<(), EnvelopeError> {
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
            match msg {
                MessageType::CookieReply => {
                    let mut resp_payload = initiation_payload.to_vec();
                    resp_payload.extend_from_slice(&payload);
                    let resend = framer
                        .encode_frame(MessageType::Initiation, &resp_payload)
                        .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?;
                    conn.send(resend)?;
                }
                MessageType::Response => return Ok(()),
                _ => {}
            }
        }
    }
    Err(EnvelopeError::HandshakeTimeout)
}
