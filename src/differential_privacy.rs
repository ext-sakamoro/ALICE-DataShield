//! differential privacy.

// Differential Privacy (Laplace Mechanism)
// ---------------------------------------------------------------------------

/// xorshift64 乱数
const fn xorshift64(state: &mut u64) -> u64 {
    let mut s = *state;
    if s == 0 {
        s = 1;
    }
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    *state = s;
    s
}

/// 一様乱数 [0, 1)
pub(crate) fn uniform(state: &mut u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    {
        (xorshift64(state) >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// ラプラスノイズ生成: Lap(0, scale) where scale = sensitivity / epsilon
/// `Laplace`(μ, b): X = μ - b × sign(u) × ln(1 - 2|u|)
pub fn laplace_noise(scale: f64, rng_state: &mut u64) -> f64 {
    let u = uniform(rng_state) - 0.5;
    let abs_u = if u < 0.0 { -u } else { u };
    // -sign(u) * scale * ln(1 - 2|u|)
    // Use Taylor approximation for ln since no_std
    let v = 1.0 - 2.0 * abs_u;
    let ln_v = ln_approx(v);
    let sign = if u < 0.0 { 1.0 } else { -1.0 };
    sign * scale * ln_v
}

/// ln近似 (`no_std`): ln(x) ≈ (x-1) - (x-1)^2/2 + (x-1)^3/3 - ... (|x-1| < 1)
pub(crate) fn ln_approx(x: f64) -> f64 {
    if x <= 0.0 {
        return -100.0;
    }
    // Use identity: ln(x) = 2 * atanh((x-1)/(x+1))
    let y = (x - 1.0) / (x + 1.0);
    let y2 = y * y;
    // Series: 2(y + y^3/3 + y^5/5 + y^7/7 + ...)
    let mut sum = y;
    let mut term = y;
    for k in 1..20 {
        term *= y2;
        sum += term / f64::from(2 * k + 1);
    }
    2.0 * sum
}

/// 差分プライバシー付きカウント: count + Lap(1/ε)
#[allow(clippy::cast_precision_loss)]
pub fn dp_count(true_count: u64, epsilon: f64, rng_state: &mut u64) -> f64 {
    let scale = 1.0 / epsilon;
    true_count as f64 + laplace_noise(scale, rng_state)
}

/// 差分プライバシー付き合計: sum + Lap(sensitivity/ε)
pub fn dp_sum(true_sum: f64, sensitivity: f64, epsilon: f64, rng_state: &mut u64) -> f64 {
    let scale = sensitivity / epsilon;
    true_sum + laplace_noise(scale, rng_state)
}
