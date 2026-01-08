use std::collections::HashMap;

use super::{
    obf_bytes::BytesObf, obf_data::DataObf, obf_datasize::DataSizeObf,
    obf_datastring::DataStringObf, obf_rand::RandObf, obf_randchars::RandCharsObf,
    obf_randdigits::RandDigitsObf, obf_timestamp::TimestampObf, Obf, SharedRng,
};
use thiserror::Error;

pub struct Chain {
    pub(crate) spec: String,
    pub(crate) obfs: Vec<Box<dyn Obf>>,
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("missing enclosing >")]
    MissingClose,
    #[error("{0}")]
    Message(String),
}

pub fn parse_chain(spec: &str) -> Result<Chain, ChainError> {
    parse_chain_with_rng(spec, SharedRng::default())
}

pub fn parse_chain_with_rng(spec: &str, rng: SharedRng) -> Result<Chain, ChainError> {
    let mut obfs: Vec<Box<dyn Obf>> = Vec::new();
    let mut remaining = spec.as_bytes();
    let builders = builders(rng);
    while let Some(start) = remaining.iter().position(|b| *b == b'<') {
        let after_start = &remaining[start + 1..];
        let end = after_start
            .iter()
            .position(|b| *b == b'>')
            .ok_or(ChainError::MissingClose)?;
        let tag = &after_start[..end];
        let tag_str = String::from_utf8_lossy(tag).trim().to_string();
        if tag_str.is_empty() {
            remaining = &after_start[end + 1..];
            continue;
        }
        let mut parts = tag_str.split_whitespace();
        let key = parts.next().unwrap();
        let builder = builders
            .get(key)
            .ok_or_else(|| ChainError::Message(format!("unknown tag <{}>", key)))?;
        let val = parts.next().unwrap_or("");
        let obf = builder(val)?;
        obfs.push(obf);
        remaining = &after_start[end + 1..];
    }

    Ok(Chain {
        spec: spec.to_string(),
        obfs,
    })
}

impl Chain {
    pub fn spec(&self) -> &str {
        &self.spec
    }

    pub fn obfuscate(&self, dst: &mut [u8], src: &[u8]) {
        let mut written = 0;
        for obf in &self.obfs {
            let obf_len = obf.obfuscated_len(src.len());
            obf.obfuscate(&mut dst[written..written + obf_len], src);
            written += obf_len;
        }
    }

    pub fn deobfuscate(&self, dst: &mut [u8], src: &[u8]) -> bool {
        let dynamic_len = src.len().saturating_sub(self.obfuscated_len(0));
        let mut written = 0;
        let mut read = 0;
        for obf in &self.obfs {
            let de_len = obf.deobfuscated_len(dynamic_len);
            let obf_len = obf.obfuscated_len(de_len);
            if read + obf_len > src.len() || written + de_len > dst.len() {
                return false;
            }
            if !obf.deobfuscate(
                &mut dst[written..written + de_len],
                &src[read..read + obf_len],
            ) {
                return false;
            }
            written += de_len;
            read += obf_len;
        }
        true
    }

    pub fn obfuscated_len(&self, n: usize) -> usize {
        self.obfs.iter().map(|o| o.obfuscated_len(n)).sum()
    }

    pub fn deobfuscated_len(&self, n: usize) -> usize {
        let dynamic_len = n.saturating_sub(self.obfuscated_len(0));
        self.obfs
            .iter()
            .map(|o| o.deobfuscated_len(dynamic_len))
            .sum()
    }
}

type Builder = Box<dyn Fn(&str) -> Result<Box<dyn Obf>, ChainError> + Send + Sync>;

fn builders(rng: SharedRng) -> HashMap<&'static str, Builder> {
    let mut map: HashMap<&'static str, Builder> = HashMap::new();
    map.insert(
        "b",
        Box::new(move |val: &str| {
            BytesObf::new(val)
                .map(|o| Box::new(o) as Box<dyn Obf>)
                .map_err(|e| ChainError::Message(e.to_string()))
        }),
    );
    map.insert(
        "t",
        Box::new(|_val: &str| Ok(Box::new(TimestampObf) as Box<dyn Obf>)),
    );
    map.insert(
        "r",
        Box::new({
            let rng = rng.clone();
            move |val: &str| {
                RandObf::new(val, rng.clone())
                    .map(|o| Box::new(o) as Box<dyn Obf>)
                    .map_err(|e| ChainError::Message(e.to_string()))
            }
        }),
    );
    map.insert(
        "rc",
        Box::new({
            let rng = rng.clone();
            move |val: &str| {
                RandCharsObf::new(val, rng.clone())
                    .map(|o| Box::new(o) as Box<dyn Obf>)
                    .map_err(|e| ChainError::Message(e.to_string()))
            }
        }),
    );
    map.insert(
        "rd",
        Box::new({
            let rng = rng.clone();
            move |val: &str| {
                RandDigitsObf::new(val, rng.clone())
                    .map(|o| Box::new(o) as Box<dyn Obf>)
                    .map_err(|e| ChainError::Message(e.to_string()))
            }
        }),
    );
    map.insert(
        "d",
        Box::new(|_val: &str| Ok(Box::new(DataObf) as Box<dyn Obf>)),
    );
    map.insert(
        "ds",
        Box::new(|_val: &str| Ok(Box::new(DataStringObf) as Box<dyn Obf>)),
    );
    map.insert(
        "dz",
        Box::new(|val: &str| {
            DataSizeObf::new(val)
                .map(|o| Box::new(o) as Box<dyn Obf>)
                .map_err(|e| ChainError::Message(e.to_string()))
        }),
    );
    map
}

#[derive(Default)]
pub struct ChainSet {
    pub i1: Option<Chain>,
    pub i2: Option<Chain>,
    pub i3: Option<Chain>,
    pub i4: Option<Chain>,
    pub i5: Option<Chain>,
}

#[derive(Debug, Error)]
pub enum ChainSetError {
    #[error("expected 5 chain specs")]
    WrongCount,
    #[error("parse chain {index}: {source}")]
    Parse { index: usize, source: ChainError },
}

pub fn parse_chains(specs: [String; 5]) -> Result<ChainSet, ChainSetError> {
    parse_chains_with_rng(specs, SharedRng::default())
}

pub fn parse_chains_with_rng(
    specs: [String; 5],
    rng: SharedRng,
) -> Result<ChainSet, ChainSetError> {
    if specs.len() != 5 {
        return Err(ChainSetError::WrongCount);
    }
    let mut parsed: [Option<Chain>; 5] = Default::default();
    for (idx, spec) in specs.into_iter().enumerate() {
        if spec.is_empty() {
            continue;
        }
        let chain =
            parse_chain_with_rng(&spec, rng.clone()).map_err(|source| ChainSetError::Parse {
                index: idx + 1,
                source,
            })?;
        parsed[idx] = Some(chain);
    }

    let [i1, i2, i3, i4, i5] = parsed;
    Ok(ChainSet { i1, i2, i3, i4, i5 })
}
