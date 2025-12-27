use thiserror::Error;

use super::header::{parse_header_with_rng, HeaderError, MagicHeader};

#[derive(Debug, Clone, Default)]
pub struct HeaderSet {
    pub h1: Option<MagicHeader>,
    pub h2: Option<MagicHeader>,
    pub h3: Option<MagicHeader>,
    pub h4: Option<MagicHeader>,
}

#[derive(Debug, Error)]
pub enum HeaderSetError {
    #[error("expected 4 header specs")]
    WrongCount,
    #[error("parse header {index}: {source}")]
    Parse { index: usize, source: HeaderError },
    #[error("headers must not overlap")]
    Overlap,
}

pub fn parse_headers(specs: [String; 4]) -> Result<HeaderSet, HeaderSetError> {
    parse_headers_with_rng(specs, super::SharedRng::default())
}

pub fn parse_headers_with_rng(
    specs: [String; 4],
    rng: super::SharedRng,
) -> Result<HeaderSet, HeaderSetError> {
    let mut parsed: [Option<MagicHeader>; 4] = Default::default();
    for (idx, spec) in specs.iter().enumerate() {
        if spec.is_empty() {
            continue;
        }
        let header =
            parse_header_with_rng(spec, rng.clone()).map_err(|source| HeaderSetError::Parse {
                index: idx + 1,
                source,
            })?;
        parsed[idx] = Some(header);
    }

    for i in 0..parsed.len() {
        for j in (i + 1)..parsed.len() {
            if let (Some(a), Some(b)) = (&parsed[i], &parsed[j]) {
                if headers_overlap(a, b) {
                    return Err(HeaderSetError::Overlap);
                }
            }
        }
    }

    Ok(HeaderSet {
        h1: parsed[0].clone(),
        h2: parsed[1].clone(),
        h3: parsed[2].clone(),
        h4: parsed[3].clone(),
    })
}

pub fn parse_headers_with_defaults(specs: [String; 4]) -> Result<HeaderSet, HeaderSetError> {
    parse_headers_with_defaults_and_rng(specs, super::SharedRng::default())
}

pub fn parse_headers_with_defaults_and_rng(
    specs: [String; 4],
    rng: super::SharedRng,
) -> Result<HeaderSet, HeaderSetError> {
    if specs.len() != 4 {
        return Err(HeaderSetError::WrongCount);
    }
    let defaults = default_header_specs();
    let mut resolved = [String::new(), String::new(), String::new(), String::new()];
    for (idx, spec) in specs.into_iter().enumerate() {
        resolved[idx] = if spec.is_empty() {
            defaults[idx].clone()
        } else {
            spec
        };
    }
    parse_headers_with_rng(resolved, rng)
}

fn headers_overlap(a: &MagicHeader, b: &MagicHeader) -> bool {
    a.validate(b.start) || a.validate(b.end) || b.validate(a.start) || b.validate(a.end)
}

pub fn default_header_specs() -> [String; 4] {
    [
        "1".to_string(),
        "2".to_string(),
        "3".to_string(),
        "4".to_string(),
    ]
}
