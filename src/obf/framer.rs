use super::{
    chain::parse_chains_with_rng,
    config::{Config, ConfigError},
    headers::{parse_headers_with_defaults_and_rng, HeaderSet, HeaderSetError},
    ChainSet, ChainSetError, SharedRng,
};
use crate::obf::chain::Chain;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FramerError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Headers(#[from] HeaderSetError),
    #[error("{0}")]
    Chains(#[from] ChainSetError),
    #[error("invalid padding")]
    InvalidPadding,
    #[error("missing header for message type {0}")]
    MissingHeader(i32),
    #[error("frame too short")]
    FrameTooShort,
    #[error("unable to determine message type")]
    AmbiguousType,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageType {
    Initiation = 1,
    Response = 2,
    CookieReply = 3,
    Transport = 4,
}

pub struct Framer {
    cfg: Config,
    headers: HeaderSet,
    chains: ChainSet,
    rng: SharedRng,
}

impl Framer {
    pub fn new(cfg: Config) -> Result<Self, FramerError> {
        Self::new_with_rng(cfg, SharedRng::default())
    }

    pub fn new_with_rng(cfg: Config, rng: SharedRng) -> Result<Self, FramerError> {
        cfg.validate()?;
        let headers = parse_headers_with_defaults_and_rng(cfg.header_specs(), rng.clone())?;
        let chains = parse_chains_with_rng(cfg.chain_specs(), rng.clone())?;
        Ok(Self {
            cfg,
            headers,
            chains,
            rng,
        })
    }

    pub fn config(&self) -> Config {
        self.cfg.clone()
    }

    /// Get the shared RNG used by this framer.
    pub fn rng(&self) -> &SharedRng {
        &self.rng
    }

    pub fn encode_frame(
        &self,
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<Vec<u8>, FramerError> {
        let padding = self.padding_for(msg_type);
        let header = self
            .header_for(msg_type)
            .ok_or(FramerError::MissingHeader(msg_type as i32))?;
        if padding < 0 {
            return Err(FramerError::InvalidPadding);
        }
        let mut datagram = Vec::with_capacity((padding as usize) + 4 + payload.len());
        if padding > 0 {
            let mut buf = vec![0u8; padding as usize];
            self.rng.fill_bytes(&mut buf);
            datagram.extend_from_slice(&buf);
        }
        datagram.extend_from_slice(&header.generate().to_le_bytes());
        datagram.extend_from_slice(payload);
        Ok(datagram)
    }

    pub fn decode_frame(&self, datagram: &[u8]) -> Result<(MessageType, Vec<u8>), FramerError> {
        if datagram.len() < 4 {
            return Err(FramerError::FrameTooShort);
        }

        // Fast path for Transport - it's the most common type
        let transport_padding = self.padding_for(MessageType::Transport);
        if transport_padding >= 0 {
            let pad_len = transport_padding as usize;
            if datagram.len() >= pad_len + 4 {
                let type_val =
                    u32::from_le_bytes(datagram[pad_len..pad_len + 4].try_into().unwrap());
                if let Some(h) = self.header_for(MessageType::Transport) {
                    if h.validate(type_val) {
                        return Ok((MessageType::Transport, datagram[pad_len + 4..].to_vec()));
                    }
                }
            }
        }

        // Fallback for others
        for msg_type in [
            MessageType::Initiation,
            MessageType::Response,
            MessageType::CookieReply,
        ] {
            let padding = self.padding_for(msg_type);
            if padding < 0 {
                continue;
            }
            let header = match self.header_for(msg_type) {
                Some(h) => h,
                None => continue,
            };
            let pad_len = padding as usize;
            if datagram.len() < pad_len + 4 {
                continue;
            }
            let type_val = u32::from_le_bytes(datagram[pad_len..pad_len + 4].try_into().unwrap());
            if header.validate(type_val) {
                return Ok((msg_type, datagram[pad_len + 4..].to_vec()));
            }
        }

        Err(FramerError::MissingHeader(-1))
    }

    pub fn junk_datagrams(&self) -> Result<Vec<Vec<u8>>, FramerError> {
        if self.cfg.jc == 0 || self.cfg.jmin <= 0 || self.cfg.jmax <= 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(self.cfg.jc as usize);
        for _ in 0..self.cfg.jc {
            let length = rand_range(&self.rng, self.cfg.jmin as usize, self.cfg.jmax as usize)?;
            let mut buf = vec![0u8; length];
            self.rng.fill_bytes(&mut buf);
            out.push(buf);
        }
        Ok(out)
    }

    pub fn signature_datagrams(&self) -> Result<Vec<Vec<u8>>, FramerError> {
        let chains: [&Option<Chain>; 5] = [
            &self.chains.i1,
            &self.chains.i2,
            &self.chains.i3,
            &self.chains.i4,
            &self.chains.i5,
        ];
        let mut out = Vec::new();
        for chain in chains.into_iter().flatten() {
            let length = chain.obfuscated_len(0);
            let mut buf = vec![0u8; length];
            let src = vec![0u8; chain.deobfuscated_len(0)];
            chain.obfuscate(&mut buf, &src);
            out.push(buf);
        }
        Ok(out)
    }

    pub fn signature_chains(&self) -> Vec<&Chain> {
        [
            &self.chains.i1,
            &self.chains.i2,
            &self.chains.i3,
            &self.chains.i4,
            &self.chains.i5,
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    pub fn signature_lengths(&self) -> Vec<usize> {
        self.signature_chains()
            .into_iter()
            .map(|c| c.obfuscated_len(0))
            .collect()
    }

    fn header_for(&self, msg_type: MessageType) -> Option<&MagicHeaderRef> {
        match msg_type {
            MessageType::Initiation => self.headers.h1.as_ref(),
            MessageType::Response => self.headers.h2.as_ref(),
            MessageType::CookieReply => self.headers.h3.as_ref(),
            MessageType::Transport => self.headers.h4.as_ref(),
        }
    }

    fn padding_for(&self, msg_type: MessageType) -> i32 {
        match msg_type {
            MessageType::Initiation => self.cfg.s1,
            MessageType::Response => self.cfg.s2,
            MessageType::CookieReply => self.cfg.s3,
            MessageType::Transport => self.cfg.s4,
        }
    }
}

type MagicHeaderRef = super::header::MagicHeader;

fn rand_range(rng: &SharedRng, min: usize, max: usize) -> Result<usize, FramerError> {
    if min > max {
        return Err(FramerError::InvalidPadding);
    }
    if min == max {
        return Ok(min);
    }
    let mut buf = [0u8; 4];
    rng.fill_bytes(&mut buf);
    let mut val = u32::from_le_bytes(buf);
    let span = (max - min + 1) as u32;
    val %= span;
    Ok(min + val as usize)
}
