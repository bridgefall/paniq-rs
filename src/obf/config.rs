use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub jc: i32,
    pub jmin: i32,
    pub jmax: i32,
    pub s1: i32,
    pub s2: i32,
    pub s3: i32,
    pub s4: i32,
    pub h1: String,
    pub h2: String,
    pub h3: String,
    pub h4: String,
    pub i1: String,
    pub i2: String,
    pub i3: String,
    pub i4: String,
    pub i5: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("jc must be non-negative")]
    NegativeJc,
    #[error("jmin/jmax must be non-negative")]
    NegativeJBounds,
    #[error("jmin must be <= jmax")]
    InvalidJRange,
    #[error("s1-s4 must be non-negative")]
    NegativeS,
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.jc < 0 {
            return Err(ConfigError::NegativeJc);
        }
        if self.jmin < 0 || self.jmax < 0 {
            return Err(ConfigError::NegativeJBounds);
        }
        if self.jmax > 0 && self.jmin > self.jmax {
            return Err(ConfigError::InvalidJRange);
        }
        if self.s1 < 0 || self.s2 < 0 || self.s3 < 0 || self.s4 < 0 {
            return Err(ConfigError::NegativeS);
        }
        Ok(())
    }

    pub fn header_specs(&self) -> [String; 4] {
        [
            self.h1.clone(),
            self.h2.clone(),
            self.h3.clone(),
            self.h4.clone(),
        ]
    }

    pub fn chain_specs(&self) -> [String; 5] {
        [
            self.i1.clone(),
            self.i2.clone(),
            self.i3.clone(),
            self.i4.clone(),
            self.i5.clone(),
        ]
    }
}
