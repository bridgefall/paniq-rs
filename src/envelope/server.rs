use crate::envelope::replay::ReplayCache;
use crate::envelope::EnvelopeError;
use crate::obf::{Framer, MessageType, SharedRng};

use super::client::PacketConn;

pub struct ServerConn<C: PacketConn> {
    conn: C,
    framer: Framer,
    state: PeerState,
    pub replay: ReplayCache,
    rng: SharedRng,
}

impl<C: PacketConn> ServerConn<C> {
    pub fn new(conn: C, framer: Framer, replay: ReplayCache, rng: SharedRng) -> Self {
        let signature_lengths = framer.signature_lengths();
        Self {
            conn,
            framer,
            state: PeerState::new(signature_lengths),
            replay,
            rng,
        }
    }

    pub fn handle_preamble(&mut self) -> Result<(MessageType, Vec<u8>), EnvelopeError> {
        loop {
            let datagram = self.conn.recv()?;
            if let Ok((msg, payload)) = self.framer.decode_frame(&datagram) {
                match msg {
                    MessageType::Initiation | MessageType::Response | MessageType::CookieReply => {
                        if msg == MessageType::Initiation && !self.state.cookie_satisfied(&payload)
                        {
                            let cookie = self.state.issue_cookie(&mut self.rng);
                            let reply = self
                                .framer
                                .encode_frame(MessageType::CookieReply, &cookie)
                                .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?;
                            self.conn.send(reply)?;
                            continue;
                        }
                        return Ok((msg, payload));
                    }
                    MessageType::Transport => {
                        self.state.track_signature(payload.len());
                    }
                }
            }
        }
    }

    pub fn send_response(
        &mut self,
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<(), EnvelopeError> {
        let frame = self
            .framer
            .encode_frame(msg_type, payload)
            .map_err(|e| EnvelopeError::Timestamp(e.to_string()))?;
        self.conn.send(frame)
    }

    pub fn into_inner(self) -> C {
        self.conn
    }
}

#[derive(Default)]
struct PeerState {
    cookie: Option<Vec<u8>>,
    signature_lengths: Vec<usize>,
    signature_seen: usize,
}

impl PeerState {
    fn new(signature_lengths: Vec<usize>) -> Self {
        Self {
            cookie: None,
            signature_lengths,
            signature_seen: 0,
        }
    }

    fn track_signature(&mut self, payload_len: usize) {
        if self
            .signature_lengths
            .get(self.signature_seen)
            .copied()
            .map(|expected| expected == payload_len)
            .unwrap_or(false)
        {
            self.signature_seen += 1;
        }
    }

    fn issue_cookie(&mut self, rng: &SharedRng) -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        rng.fill_bytes(&mut buf);
        self.cookie = Some(buf.clone());
        buf
    }

    fn cookie_satisfied(&self, payload: &[u8]) -> bool {
        match &self.cookie {
            None => false,
            Some(cookie) => payload.ends_with(cookie),
        }
    }
}
