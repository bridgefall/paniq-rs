use std::ops::RangeInclusive;
use thiserror::Error;

use super::SharedRng;

#[derive(Debug, Clone)]
pub struct MagicHeader {
    pub start: u32,
    pub end: u32,
    rng: SharedRng,
}

#[derive(Debug, Error)]
pub enum HeaderError {
    #[error("bad format")]
    BadFormat,
    #[error("failed to parse {0}: {1}")]
    ParseValue(String, String),
    #[error("wrong range specified")]
    InvalidRange,
}

pub fn parse_header(spec: &str) -> Result<MagicHeader, HeaderError> {
    parse_header_with_rng(spec, SharedRng::default())
}

pub fn parse_header_with_rng(spec: &str, rng: SharedRng) -> Result<MagicHeader, HeaderError> {
    let parts: Vec<&str> = spec.split('-').collect();
    if parts.is_empty() || parts.len() > 2 {
        return Err(HeaderError::BadFormat);
    }
    let parse_part = |s: &str| -> Result<u32, HeaderError> {
        s.parse::<u32>()
            .map_err(|e| HeaderError::ParseValue(s.to_string(), e.to_string()))
    };
    let start = parse_part(parts[0])?;
    let end = if parts.len() > 1 {
        parse_part(parts[1])?
    } else {
        start
    };
    if end < start {
        return Err(HeaderError::InvalidRange);
    }
    Ok(MagicHeader { start, end, rng })
}

impl MagicHeader {
    pub fn with_rng(mut self, rng: SharedRng) -> Self {
        self.rng = rng;
        self
    }

    pub fn gen_spec(&self) -> String {
        if self.start == self.end {
            return format!("{}", self.start);
        }
        format!("{}-{}", self.start, self.end)
    }

    pub fn validate(&self, val: u32) -> bool {
        RangeInclusive::new(self.start, self.end).contains(&val)
    }

    pub fn generate(&self) -> u32 {
        if self.start == self.end {
            return self.start;
        }
        let mut buf = [0u8; 4];
        self.rng.fill_bytes(&mut buf);
        let span = self.end - self.start + 1;
        let mut val = u32::from_le_bytes(buf);
        val %= span;
        self.start + val
    }
}
