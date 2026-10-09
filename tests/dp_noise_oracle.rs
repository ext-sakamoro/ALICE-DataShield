//! 差分プライバシーの noise 源を「法則」として固定する
//!
//! ⚠️ ここで固定するのは 3 つの性質で、どれが欠けても ε の主張が成立しない
//!
//! 1. **予測不能性** — 鍵を知らない側は noise を再現できない (noise を引き去られない)
//! 2. **再現性** — 鍵を知る側は同じ noise を再現できる (replay / 監査 / 試験)
//! 3. **分布** — Laplace(0, b) の平均 0 / 分散 2b² (ε の計算と実際の noise が一致する)
//!
//! 2026-10-09 までの実装は 1 と 3 の両方を満たしていなかった:
//! - `xorshift64` + 呼び出し側が持つ 64 bit 状態 ⇒ 出力数語から状態が解ける (F2 線形)
//! - `ln_approx` の 20 項打ち切り + 定義域外で `-100.0` を返す magic 値 ⇒ 分布が歪む
//!
//! 期待値の出所: Laplace 分布の定義 (平均 0、分散 2b²) と、`alice-det-math` の `ln64`
//! (bit 一致・1 ulp 保証) ⚠️ 実装の出力から書き起こした値は 1 つも無い

use alice_datashield::csprng::SecureRng;
use alice_datashield::differential_privacy::{dp_count, dp_sum, DpNoise};

/// 試験用の鍵 (本番は OS entropy か呼び出し側が秘密に保つ 32 byte)
fn key(n: u8) -> [u8; 32] {
    [n; 32]
}

#[test]
fn the_same_key_reproduces_the_same_noise() {
    let mut a = DpNoise::with_key(1.0, key(7));
    let mut b = DpNoise::with_key(1.0, key(7));
    let xs: Vec<u64> = (0..256).map(|_| a.laplace().to_bits()).collect();
    let ys: Vec<u64> = (0..256).map(|_| b.laplace().to_bits()).collect();
    assert_eq!(xs, ys, "同じ鍵は同じ noise 列を返す (replay / 監査が依る)");
    // 空振り防止: 定数を返していない
    assert!(
        xs.iter().collect::<std::collections::BTreeSet<_>>().len() > 240,
        "256 件中の相異なる値が {} しかない",
        xs.iter().collect::<std::collections::BTreeSet<_>>().len()
    );
}

#[test]
fn a_different_key_gives_a_different_noise_sequence() {
    let mut a = DpNoise::with_key(1.0, key(7));
    let mut b = DpNoise::with_key(1.0, key(8));
    let xs: Vec<u64> = (0..64).map(|_| a.laplace().to_bits()).collect();
    let ys: Vec<u64> = (0..64).map(|_| b.laplace().to_bits()).collect();
    let shared = xs.iter().zip(ys.iter()).filter(|(x, y)| x == y).count();
    assert_eq!(
        shared, 0,
        "鍵が違うのに {shared} 件が一致した (再現できてしまう)"
    );
}

#[test]
fn the_distribution_is_laplace_with_mean_zero_and_variance_two_b_squared() {
    // 期待値は Laplace(0, b) の定義から: E[X] = 0、Var[X] = 2b²
    for b in [0.5f64, 1.0, 4.0] {
        let mut n = DpNoise::with_key(b, key(42));
        let count = 200_000;
        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        for _ in 0..count {
            let x = n.laplace();
            sum += x;
            sum_sq += x * x;
        }
        let mean = sum / f64::from(count);
        let var = sum_sq / f64::from(count) - mean * mean;
        assert!(
            mean.abs() < 0.05 * b,
            "b = {b}: 平均 {mean} が 0 から離れすぎている"
        );
        let want = 2.0 * b * b;
        assert!(
            ((var - want) / want).abs() < 0.05,
            "b = {b}: 分散 {var} が 2b² = {want} と合わない"
        );
    }
}

#[test]
fn both_tails_are_produced() {
    // 符号が片方に偏っていないこと (逆関数法の符号の取り違えを捕まえる)
    let mut n = DpNoise::with_key(1.0, key(3));
    let (mut neg, mut pos) = (0u32, 0u32);
    for _ in 0..10_000 {
        if n.laplace() < 0.0 {
            neg += 1;
        } else {
            pos += 1;
        }
    }
    assert!(
        neg > 4_500 && pos > 4_500,
        "符号の偏り: 負 {neg} / 正 {pos}"
    );
}

#[test]
fn the_noise_never_returns_a_magic_constant() {
    // 旧実装は定義域外で -100.0 を返していた (確率 0 の事象ではなく、現実に通る経路)
    let mut n = DpNoise::with_key(1.0, key(5));
    for _ in 0..200_000 {
        let x = n.laplace();
        assert!(x.is_finite(), "有限でない noise {x}");
        assert!(
            (x - -100.0).abs() > 1e-12 || x.abs() < 1e-9,
            "magic 値 -100.0 が出た"
        );
    }
}

#[test]
fn dp_count_and_dp_sum_add_noise_of_the_declared_scale() {
    // ε が小さいほど noise が大きい (scale = sensitivity / ε)
    let spread = |eps: f64| -> f64 {
        let mut n = DpNoise::with_key(1.0 / eps, key(11));
        let xs: Vec<f64> = (0..20_000).map(|_| n.laplace()).collect();
        let mean = xs.iter().sum::<f64>()
            / f64::from(u32::try_from(xs.len()).expect("件数は u32 に収まる"));
        (xs.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>()
            / f64::from(u32::try_from(xs.len()).expect("件数は u32 に収まる")))
        .sqrt()
    };
    let (tight, loose) = (spread(4.0), spread(0.25));
    assert!(
        loose > tight * 8.0,
        "ε = 0.25 の広がり {loose} が ε = 4 の {tight} に対して小さすぎる"
    );

    // 公開 API が noise を実際に足していること (素通しでない)
    let mut r1 = SecureRng::from_key(key(13));
    let mut r2 = SecureRng::from_key(key(13));
    let c = dp_count(1_000, 1.0, &mut r1).expect("eps = 1 は有効");
    let s = dp_sum(500.0, 10.0, 1.0, &mut r2).expect("有効な引数");
    assert!(
        (c - 1_000.0).abs() > 0.0,
        "dp_count が noise を足していない"
    );
    assert!((s - 500.0).abs() > 0.0, "dp_sum が noise を足していない");
    // 同じ鍵・同じ呼び出し順なら再現する
    let mut r3 = SecureRng::from_key(key(13));
    assert_eq!(
        dp_count(1_000, 1.0, &mut r3).expect("有効").to_bits(),
        c.to_bits()
    );

    // ⚠️ ε が実際に効くこと (受け取って無視していないか = 配線の変異を殺す)
    let widths: Vec<f64> = [4.0f64, 0.25]
        .iter()
        .map(|&eps| {
            let mut r = SecureRng::from_key(key(17));
            let xs: Vec<f64> = (0..4_000)
                .map(|i| dp_count(0, eps, &mut r).expect("有効") - f64::from(i) * 0.0)
                .collect();
            let m = xs.iter().sum::<f64>()
                / f64::from(u32::try_from(xs.len()).expect("件数は u32 に収まる"));
            (xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>()
                / f64::from(u32::try_from(xs.len()).expect("件数は u32 に収まる")))
            .sqrt()
        })
        .collect();
    assert!(
        widths[1] > widths[0] * 8.0,
        "ε = 0.25 の広がり {} が ε = 4 の {} に対して小さすぎる (ε が無視されている)",
        widths[1],
        widths[0]
    );

    // 不正な ε / sensitivity は拒否する
    let mut r = SecureRng::from_key(key(19));
    assert!(dp_count(1, 0.0, &mut r).is_err());
    assert!(dp_count(1, f64::NAN, &mut r).is_err());
    assert!(dp_sum(1.0, 0.0, 1.0, &mut r).is_err());
}

#[test]
fn an_invalid_scale_is_refused_instead_of_silently_producing_garbage() {
    // 旧実装は scale = 0 / 負 / NaN をそのまま通した
    assert!(
        DpNoise::try_with_key(0.0, key(1)).is_err(),
        "scale = 0 を受理した"
    );
    assert!(
        DpNoise::try_with_key(-1.0, key(1)).is_err(),
        "負の scale を受理した"
    );
    assert!(
        DpNoise::try_with_key(f64::NAN, key(1)).is_err(),
        "NaN の scale を受理した"
    );
    assert!(
        DpNoise::try_with_key(f64::INFINITY, key(1)).is_err(),
        "無限大の scale を受理した"
    );
    assert!(DpNoise::try_with_key(1e-6, key(1)).is_ok());
}
