//! generalization.

// Generalization (for k-anonymity)
// ---------------------------------------------------------------------------

/// 数値の一般化: value → range bucket
#[must_use]
pub fn generalize_numeric(value: f64, bucket_size: f64) -> (f64, f64) {
    let lo = floor_f64(value / bucket_size) * bucket_size;
    (lo, lo + bucket_size)
}

#[allow(clippy::cast_possible_truncation)]
pub(crate) fn floor_f64(x: f64) -> f64 {
    let i = x as i64;
    #[allow(clippy::cast_precision_loss)]
    if (i as f64) > x {
        (i - 1) as f64
    } else {
        i as f64
    }
}
