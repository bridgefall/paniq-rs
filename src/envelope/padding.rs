use rand::Rng;

#[derive(Debug, Clone, Copy)]
pub struct PaddingPolicy {
    pub enabled: bool,
    pub min: usize,
    pub max: usize,
    pub burst_min: usize,
    pub burst_max: usize,
    pub burst_prob: f64,
}

impl PaddingPolicy {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            min: 0,
            max: 0,
            burst_min: 0,
            burst_max: 0,
            burst_prob: 0.0,
        }
    }

    pub fn max_padding(&self) -> usize {
        if !self.enabled {
            return 0;
        }
        self.max.max(self.burst_max)
    }

    pub fn padding_len<R: Rng>(
        &self,
        payload_len: usize,
        max_payload: usize,
        rng: &mut R,
    ) -> usize {
        if !self.enabled {
            return 0;
        }
        let base_range = if rng.gen_bool(self.burst_prob.clamp(0.0, 1.0)) {
            (self.burst_min, self.burst_max)
        } else {
            (self.min, self.max)
        };
        let mut pad = if base_range.1 <= base_range.0 {
            base_range.0
        } else {
            rng.gen_range(base_range.0..=base_range.1)
        };
        let total = payload_len.saturating_add(pad);
        if total > max_payload {
            pad = max_payload.saturating_sub(payload_len);
        }
        pad
    }
}
