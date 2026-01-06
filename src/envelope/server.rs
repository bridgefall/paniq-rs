use crate::envelope::replay::ReplayCache;
use crate::envelope::EnvelopeError;
use crate::obf::{Framer, MessageType, SharedRng};

use super::client::PacketConn;

pub struct ServerConn<C: PacketConn> {
    conn: C,
    framer: Framer,
    state: PeerState,
    pub replay: ReplayCache,
}

impl<C: PacketConn> ServerConn<C> {
    pub fn new(conn: C, framer: Framer, replay: ReplayCache, _rng: SharedRng) -> Self {
        let signature_lengths = framer.signature_lengths();
        Self {
            conn,
            framer,
            state: PeerState::new(signature_lengths),
            replay,
        }
    }

    pub fn handle_preamble(&mut self) -> Result<(MessageType, Vec<u8>), EnvelopeError> {
        loop {
            let datagram = self.conn.recv()?;
            if let Ok((msg, payload)) = self.framer.decode_frame(&datagram) {
                match msg {
                    MessageType::Initiation | MessageType::Response | MessageType::CookieReply => {
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
    signature_lengths: Vec<usize>,
    signature_seen: usize,
}

impl PeerState {
    fn new(signature_lengths: Vec<usize>) -> Self {
        Self {
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
}
