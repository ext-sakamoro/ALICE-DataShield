//! 差分プライバシー (Laplace 機構)
//!
//! # 2026-10-09 に直した 2 つの欠陥
//!
//! ⚠️ **(1) noise が予測可能だった** — `xorshift64` + 呼び出し側が持つ 64 bit 状態
//! F2 線形なので出力数語から内部状態が解け、noise を引き去れた
//! ⇒ [`crate::csprng::SecureRng`] (ChaCha20、鍵基準) に替えた
//!
//! ⚠️ **(2) 分布が歪んでいた** — `ln` を 20 項の級数で近似し、定義域外では `-100.0` を
//! 返していた (確率 0 の事象ではなく `u → 0` の近傍で現実に通る経路)
//! ⇒ `alice-det-math` の [`ln64`] (bit 一致・1 ulp 保証) に替え、magic 値を削除した
//!
//! # 残っている既知の限界 (次段で対処)
//!
//! ⚠️ 浮動小数点の逆関数法は **Mironov 2012 (LSB 攻撃)** の対象 完全な CSPRNG でも
//! `scale * ln(u)` の下位 bit から `u` が復元でき、ε-DP が理論値より弱くなる
//! ⇒ snapping mechanism (出力を 2 の冪の格子に丸める) を次の commit で入れる
//! それまでこの module の ε は「理想的な実数演算での値」であって実機の保証ではない

use crate::csprng::{EntropyError, SecureRng};
use alice_det_math::ln64;

/// scale (= sensitivity / ε) が使える値でない
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpError {
    /// scale が有限の正値でない (0 / 負 / NaN / 無限大)
    ///
    /// ⚠️ 旧実装はこれらをそのまま通し、noise が 0 や NaN になっても気付けなかった
    InvalidScale,
    /// OS entropy が取れなかった
    Entropy(EntropyError),
}

impl core::fmt::Display for DpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidScale => {
                f.write_str("scale must be finite and > 0 (scale = sensitivity / epsilon)")
            }
            Self::Entropy(e) => write!(f, "{e}"),
        }
    }
}

/// Laplace noise 生成器
///
/// 決定論の基準は **32 byte の秘密鍵** 同じ鍵なら同じ noise 列 (replay / 監査 / 試験)、
/// 鍵を知らない側からは予測も再現もできない
///
/// ⚠️ 鍵を時刻・連番・固定値から作らない (推測できる値を基準にすると noise を
/// 引き去られる) `no_std` では [`Self::with_key`] に呼び出し側が秘密の鍵を渡す
#[derive(Clone, Debug)]
pub struct DpNoise {
    /// Laplace の scale b (= sensitivity / ε)
    scale: f64,
    rng: SecureRng,
}

impl DpNoise {
    /// 鍵から作る
    ///
    /// # Panics
    ///
    /// `scale` が有限の正値でない時 失敗を扱いたい呼び出し側は [`Self::try_with_key`]
    #[must_use]
    pub fn with_key(scale: f64, key: [u8; 32]) -> Self {
        Self::try_with_key(scale, key).expect("scale must be finite and > 0")
    }

    /// 鍵から作る (失敗を返す形)
    ///
    /// # Errors
    ///
    /// `scale` が有限の正値でない時に [`DpError::InvalidScale`]
    pub fn try_with_key(scale: f64, key: [u8; 32]) -> Result<Self, DpError> {
        if !scale.is_finite() || scale <= 0.0 {
            return Err(DpError::InvalidScale);
        }
        Ok(Self {
            scale,
            rng: SecureRng::from_key(key),
        })
    }

    /// OS entropy から鍵を取る
    ///
    /// # Errors
    ///
    /// `scale` が不正な時 / entropy source が使えない時 ⚠️ **時刻へ fallback しない**
    pub fn try_from_entropy(scale: f64) -> Result<Self, DpError> {
        if !scale.is_finite() || scale <= 0.0 {
            return Err(DpError::InvalidScale);
        }
        Ok(Self {
            scale,
            rng: SecureRng::try_from_entropy().map_err(DpError::Entropy)?,
        })
    }

    /// Laplace(0, scale) を 1 つ引く
    ///
    /// 逆関数法: 符号を 1 bit、大きさを `-b·ln(u)` (`u ∈ (0, 1]`) から作る
    /// ⚠️ `u` は 0 を返さない ([`SecureRng::next_f64_open01`]) ので `ln` は有限
    #[inline]
    pub fn laplace(&mut self) -> f64 {
        // 符号は keystream の 1 bit から取る (u の符号を流用すると
        // 大きさと符号が相関し、片側の裾が薄くなる)
        let sign_bit = self.rng.next_u64() & 1;
        let u = self.rng.next_f64_open01();
        let magnitude = -self.scale * ln64(u);
        if sign_bit == 0 {
            -magnitude
        } else {
            magnitude
        }
    }

    /// scale を返す
    #[inline]
    #[must_use]
    pub const fn scale(&self) -> f64 {
        self.scale
    }
}

impl DpNoise {
    /// 既存の列から 1 回だけ引くための内部構築 (鍵を複製せず、渡された列を進める)
    ///
    /// `dp_count` / `dp_sum` は乱数源だけを受け取り scale を ε から導くので、
    /// その場で scale を束ねるために使う
    const fn from_parts(scale: f64, rng: &mut SecureRng) -> BorrowedNoise<'_> {
        BorrowedNoise { scale, rng }
    }
}

/// 借用した列で 1 回引く (`DpNoise` と同じ逆関数法)
struct BorrowedNoise<'a> {
    scale: f64,
    rng: &'a mut SecureRng,
}

impl BorrowedNoise<'_> {
    #[inline]
    fn laplace(&mut self) -> f64 {
        let sign_bit = self.rng.next_u64() & 1;
        let u = self.rng.next_f64_open01();
        let magnitude = -self.scale * ln64(u);
        if sign_bit == 0 {
            -magnitude
        } else {
            magnitude
        }
    }
}

/// 差分プライバシー付きカウント: `count + Lap(1/ε)`
///
/// 感度 1 (1 人の出入りで count が 1 変わる) を前提に `scale = 1/ε` を**ここで作る**
///
/// ⚠️ **ε を受け取って無視してはいけない** — scale を外から渡す設計にすると、
/// 呼び出し側が渡した ε と実際の noise の大きさが食い違っても誰も気付かない
/// (引数が既定値のまま無視される形で、配線の変異が恒等になる) 乱数源だけを受け取り、
/// scale は ε から導く
///
/// # Errors
///
/// `epsilon` が有限の正値でない時に [`DpError::InvalidScale`]
pub fn dp_count(true_count: u64, epsilon: f64, rng: &mut SecureRng) -> Result<f64, DpError> {
    if !epsilon.is_finite() || epsilon <= 0.0 {
        return Err(DpError::InvalidScale);
    }
    let mut noise = DpNoise::from_parts(1.0 / epsilon, rng);
    #[allow(clippy::cast_precision_loss)]
    let base = true_count as f64;
    Ok(base + noise.laplace())
}

/// 差分プライバシー付き合計: `sum + Lap(sensitivity/ε)`
///
/// # Errors
///
/// `sensitivity` / `epsilon` が有限の正値でない時に [`DpError::InvalidScale`]
pub fn dp_sum(
    true_sum: f64,
    sensitivity: f64,
    epsilon: f64,
    rng: &mut SecureRng,
) -> Result<f64, DpError> {
    if !sensitivity.is_finite() || sensitivity <= 0.0 || !epsilon.is_finite() || epsilon <= 0.0 {
        return Err(DpError::InvalidScale);
    }
    let mut noise = DpNoise::from_parts(sensitivity / epsilon, rng);
    Ok(true_sum + noise.laplace())
}
