//! ALICE-DataShield — Data masking and differential privacy
//!
//! データマスキング、k-匿名化、差分プライバシー（ラプラスノイズ）

#![no_std]
extern crate alloc;
use alloc::{string::String, vec::Vec};

// ---------------------------------------------------------------------------
// Masking
// ---------------------------------------------------------------------------

/// 文字列マスキング: 先頭n文字を残して'*'に置換
#[must_use]
pub fn mask_string(s: &str, keep_prefix: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if i < keep_prefix {
            result.push(c);
        } else {
            result.push('*');
        }
    }
    result
}

/// メールアドレスマスキング: `user@domain` → `u***@domain`
#[must_use]
pub fn mask_email(email: &str) -> String {
    email.find('@').map_or_else(
        || mask_string(email, 1),
        |at_pos| {
            let user = &email[..at_pos];
            let domain = &email[at_pos..];
            let mut masked = String::new();
            if let Some(first) = user.chars().next() {
                masked.push(first);
                for _ in 1..user.len() {
                    masked.push('*');
                }
            }
            masked.push_str(domain);
            masked
        },
    )
}

/// クレジットカード番号マスキング: 末尾4桁のみ表示
#[must_use]
pub fn mask_card(number: &str) -> String {
    let digits: Vec<char> = number.chars().filter(char::is_ascii_digit).collect();
    if digits.len() < 4 {
        return mask_string(number, 0);
    }
    let mut result = String::new();
    for _ in 0..digits.len() - 4 {
        result.push('*');
    }
    for &d in &digits[digits.len() - 4..] {
        result.push(d);
    }
    result
}

// ---------------------------------------------------------------------------
// K-Anonymity
// ---------------------------------------------------------------------------

/// k-匿名性チェック: 各等価クラスのレコード数がk以上か
#[must_use]
pub fn check_k_anonymity(groups: &[usize], k: usize) -> bool {
    groups.iter().all(|&count| count >= k)
}

/// 等価クラスサイズの計算 (quasi-identifier hash → count)
#[must_use]
pub fn compute_equivalence_classes(quasi_ids: &[u64]) -> Vec<usize> {
    let mut sorted = quasi_ids.to_vec();
    sorted.sort_unstable();
    let mut classes = Vec::new();
    if sorted.is_empty() {
        return classes;
    }
    let mut count = 1usize;
    for i in 1..sorted.len() {
        if sorted[i] == sorted[i - 1] {
            count += 1;
        } else {
            classes.push(count);
            count = 1;
        }
    }
    classes.push(count);
    classes
}

// ---------------------------------------------------------------------------
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
fn uniform(state: &mut u64) -> f64 {
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
fn ln_approx(x: f64) -> f64 {
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

// ---------------------------------------------------------------------------
// Generalization (for k-anonymity)
// ---------------------------------------------------------------------------

/// 数値の一般化: value → range bucket
#[must_use]
pub fn generalize_numeric(value: f64, bucket_size: f64) -> (f64, f64) {
    let lo = floor_f64(value / bucket_size) * bucket_size;
    (lo, lo + bucket_size)
}

#[allow(clippy::cast_possible_truncation)]
fn floor_f64(x: f64) -> f64 {
    let i = x as i64;
    #[allow(clippy::cast_precision_loss)]
    if (i as f64) > x {
        (i - 1) as f64
    } else {
        i as f64
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataShieldError {
    InsufficientAnonymity,
    InvalidEpsilon,
}

impl core::fmt::Display for DataShieldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientAnonymity => write!(f, "insufficient anonymity"),
            Self::InvalidEpsilon => write!(f, "invalid epsilon"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn mask_basic() {
        assert_eq!(mask_string("hello world", 3), "hel********");
    }

    #[test]
    fn mask_email_basic() {
        assert_eq!(mask_email("alice@example.com"), "a****@example.com");
    }

    #[test]
    fn mask_card_basic() {
        assert_eq!(mask_card("4111111111111111"), "************1111");
    }

    #[test]
    fn k_anonymity_pass() {
        assert!(check_k_anonymity(&[3, 5, 4], 3));
    }

    #[test]
    fn k_anonymity_fail() {
        assert!(!check_k_anonymity(&[3, 1, 4], 3));
    }

    #[test]
    fn equivalence_classes() {
        let ids = vec![1, 1, 2, 2, 2, 3];
        let classes = compute_equivalence_classes(&ids);
        assert_eq!(classes, vec![2, 3, 1]);
    }

    #[test]
    fn dp_count_noisy() {
        let mut rng = 42u64;
        let noisy = dp_count(1000, 1.0, &mut rng);
        // Should be close to 1000 but not exact
        assert!((noisy - 1000.0).abs() < 50.0);
    }

    #[test]
    fn dp_sum_noisy() {
        let mut rng = 42u64;
        let noisy = dp_sum(500.0, 10.0, 1.0, &mut rng);
        assert!((noisy - 500.0).abs() < 100.0);
    }

    #[test]
    fn laplace_noise_distribution() {
        let mut rng = 12345u64;
        let mut sum = 0.0;
        let n = 1000;
        for _ in 0..n {
            sum += laplace_noise(1.0, &mut rng);
        }
        #[allow(clippy::cast_precision_loss)]
        let mean = sum / f64::from(n);
        assert!(mean.abs() < 1.0); // mean ≈ 0
    }

    #[test]
    fn generalize_numeric_basic() {
        let (lo, hi) = generalize_numeric(25.0, 10.0);
        assert!((lo - 20.0).abs() < 0.01);
        assert!((hi - 30.0).abs() < 0.01);
    }

    #[test]
    fn ln_approx_accuracy() {
        // ln(0.5) ≈ -0.693
        let v = ln_approx(0.5);
        assert!((v - (-core::f64::consts::LN_2)).abs() < 0.01);
    }

    #[test]
    fn mask_empty() {
        assert_eq!(mask_string("", 3), "");
    }

    // -----------------------------------------------------------------------
    // mask_string 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn mask_string_keep_zero() {
        // 全文字マスク
        assert_eq!(mask_string("secret", 0), "******");
    }

    #[test]
    fn mask_string_keep_exceeds_len() {
        // keep_prefix が文字列長を超える場合、全文字そのまま
        assert_eq!(mask_string("abc", 10), "abc");
    }

    #[test]
    fn mask_string_keep_equals_len() {
        // keep_prefix がちょうど文字列長と同じ
        assert_eq!(mask_string("abc", 3), "abc");
    }

    #[test]
    fn mask_string_single_char() {
        // 1文字の文字列
        assert_eq!(mask_string("A", 0), "*");
        assert_eq!(mask_string("A", 1), "A");
    }

    #[test]
    fn mask_string_multibyte() {
        // 日本語（マルチバイト文字）のマスキング
        assert_eq!(mask_string("東京都", 1), "東**");
    }

    #[test]
    fn mask_string_with_spaces() {
        // 空白を含む文字列
        assert_eq!(mask_string("a b c", 2), "a ***");
    }

    #[test]
    fn mask_string_with_symbols() {
        // 記号を含む文字列
        assert_eq!(mask_string("!@#$%", 2), "!@***");
    }

    #[test]
    fn mask_string_keep_one() {
        // 先頭1文字のみ残す
        assert_eq!(mask_string("password", 1), "p*******");
    }

    #[test]
    fn mask_string_unicode_emoji() {
        // 絵文字を含むマスキング
        let result = mask_string("Hi🎉!", 2);
        assert_eq!(result, "Hi**");
    }

    #[test]
    fn mask_string_numeric() {
        // 数字文字列のマスキング
        assert_eq!(mask_string("12345", 2), "12***");
    }

    #[test]
    fn mask_string_long_prefix() {
        // 長い文字列で先頭5文字保持
        assert_eq!(mask_string("abcdefghij", 5), "abcde*****");
    }

    // -----------------------------------------------------------------------
    // mask_email 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn mask_email_no_at() {
        // @がない場合はmask_string(s, 1)にフォールバック
        assert_eq!(mask_email("noatsign"), "n*******");
    }

    #[test]
    fn mask_email_empty() {
        // 空文字列
        assert_eq!(mask_email(""), "");
    }

    #[test]
    fn mask_email_at_only() {
        // @のみ
        let result = mask_email("@");
        assert_eq!(result, "@");
    }

    #[test]
    fn mask_email_single_char_user() {
        // user部分が1文字
        assert_eq!(mask_email("a@b.com"), "a@b.com");
    }

    #[test]
    fn mask_email_long_user() {
        // user部分が長い
        assert_eq!(mask_email("longuser@example.com"), "l*******@example.com");
    }

    #[test]
    fn mask_email_two_char_user() {
        // user部分が2文字
        assert_eq!(mask_email("ab@c.com"), "a*@c.com");
    }

    #[test]
    fn mask_email_subdomain() {
        // サブドメイン付きドメイン
        assert_eq!(mask_email("user@sub.example.com"), "u***@sub.example.com");
    }

    #[test]
    fn mask_email_plus_addressing() {
        // +アドレッシング
        assert_eq!(mask_email("user+tag@example.com"), "u*******@example.com");
    }

    #[test]
    fn mask_email_dot_in_user() {
        // user部分にドット
        assert_eq!(
            mask_email("first.last@example.com"),
            "f*********@example.com"
        );
    }

    #[test]
    fn mask_email_numeric_user() {
        // 数字のみのuser
        assert_eq!(mask_email("123@example.com"), "1**@example.com");
    }

    // -----------------------------------------------------------------------
    // mask_card 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn mask_card_fewer_than_4_digits() {
        // 4桁未満は全マスク
        assert_eq!(mask_card("123"), "***");
    }

    #[test]
    fn mask_card_exactly_4_digits() {
        // ちょうど4桁は全表示
        assert_eq!(mask_card("1234"), "1234");
    }

    #[test]
    fn mask_card_with_hyphens() {
        // ハイフン区切り（数字のみ抽出される）
        assert_eq!(mask_card("4111-1111-1111-1111"), "************1111");
    }

    #[test]
    fn mask_card_with_spaces() {
        // スペース区切り
        assert_eq!(mask_card("4111 1111 1111 1111"), "************1111");
    }

    #[test]
    fn mask_card_empty() {
        // 空文字列
        assert_eq!(mask_card(""), "");
    }

    #[test]
    fn mask_card_no_digits() {
        // 数字なし → 4桁未満なのでmask_string(number, 0)にフォールバック
        assert_eq!(mask_card("abcdef"), "******");
    }

    #[test]
    fn mask_card_five_digits() {
        // 5桁
        assert_eq!(mask_card("12345"), "*2345");
    }

    #[test]
    fn mask_card_mixed_chars() {
        // 数字以外の文字混在 → 数字のみ抽出: 1,2,3,4,5 → 末尾4桁=2345
        assert_eq!(mask_card("a1b2c3d4e5"), "*2345");
    }

    #[test]
    fn mask_card_amex_15_digits() {
        // AMEX 15桁
        let result = mask_card("378282246310005");
        assert_eq!(result, "***********0005");
    }

    #[test]
    fn mask_card_single_digit() {
        // 1桁のみ
        assert_eq!(mask_card("5"), "*");
    }

    // -----------------------------------------------------------------------
    // check_k_anonymity 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn k_anonymity_empty_groups() {
        // 空配列は常にtrue（all()が空で真）
        assert!(check_k_anonymity(&[], 5));
    }

    #[test]
    fn k_anonymity_k_zero() {
        // k=0は常にtrue
        assert!(check_k_anonymity(&[1, 2, 3], 0));
    }

    #[test]
    fn k_anonymity_k_one() {
        // k=1は全てのグループが1以上なら真
        assert!(check_k_anonymity(&[1, 1, 1], 1));
    }

    #[test]
    fn k_anonymity_single_group_pass() {
        // 単一グループで条件を満たす
        assert!(check_k_anonymity(&[5], 5));
    }

    #[test]
    fn k_anonymity_single_group_fail() {
        // 単一グループで条件を満たさない
        assert!(!check_k_anonymity(&[4], 5));
    }

    #[test]
    fn k_anonymity_all_same() {
        // 全グループ同じサイズ
        assert!(check_k_anonymity(&[3, 3, 3, 3], 3));
    }

    #[test]
    fn k_anonymity_boundary() {
        // 境界値: ちょうどk
        assert!(check_k_anonymity(&[5, 5, 5], 5));
        assert!(!check_k_anonymity(&[5, 4, 5], 5));
    }

    #[test]
    fn k_anonymity_large_k() {
        // 大きなk値
        assert!(!check_k_anonymity(&[100, 99, 100], 100));
    }

    // -----------------------------------------------------------------------
    // compute_equivalence_classes 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn equivalence_classes_empty() {
        // 空配列
        let classes = compute_equivalence_classes(&[]);
        assert!(classes.is_empty());
    }

    #[test]
    fn equivalence_classes_single() {
        // 1要素
        let classes = compute_equivalence_classes(&[42]);
        assert_eq!(classes, vec![1]);
    }

    #[test]
    fn equivalence_classes_all_same() {
        // 全て同一
        let classes = compute_equivalence_classes(&[5, 5, 5, 5]);
        assert_eq!(classes, vec![4]);
    }

    #[test]
    fn equivalence_classes_all_unique() {
        // 全て異なる
        let classes = compute_equivalence_classes(&[1, 2, 3, 4]);
        assert_eq!(classes, vec![1, 1, 1, 1]);
    }

    #[test]
    fn equivalence_classes_reverse_sorted() {
        // 逆順入力でもソート後正しく計算
        let classes = compute_equivalence_classes(&[3, 2, 1, 3, 2, 1]);
        assert_eq!(classes, vec![2, 2, 2]);
    }

    #[test]
    fn equivalence_classes_two_groups() {
        // 2つのグループ
        let classes = compute_equivalence_classes(&[10, 20, 10, 20, 10]);
        assert_eq!(classes, vec![3, 2]);
    }

    #[test]
    fn equivalence_classes_large_ids() {
        // 大きなID値
        let classes = compute_equivalence_classes(&[u64::MAX, u64::MAX, u64::MAX - 1]);
        assert_eq!(classes, vec![1, 2]);
    }

    #[test]
    fn equivalence_classes_zero_ids() {
        // ゼロのID
        let classes = compute_equivalence_classes(&[0, 0, 0, 1, 1]);
        assert_eq!(classes, vec![3, 2]);
    }

    #[test]
    fn equivalence_classes_single_pair() {
        // 1ペアのみ
        let classes = compute_equivalence_classes(&[7, 7]);
        assert_eq!(classes, vec![2]);
    }

    #[test]
    fn equivalence_classes_many_groups() {
        // 多数のグループ
        let ids = vec![1, 2, 3, 4, 5, 1, 2, 3, 4, 5];
        let classes = compute_equivalence_classes(&ids);
        assert_eq!(classes, vec![2, 2, 2, 2, 2]);
    }

    // -----------------------------------------------------------------------
    // laplace_noise 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn laplace_noise_scale_zero() {
        // scale=0 → ノイズなし
        let mut rng = 42u64;
        let noise = laplace_noise(0.0, &mut rng);
        assert!((noise).abs() < f64::EPSILON);
    }

    #[test]
    fn laplace_noise_different_seeds() {
        // 異なるシードで異なるノイズ
        let mut rng1 = 1u64;
        let mut rng2 = 2u64;
        let n1 = laplace_noise(1.0, &mut rng1);
        let n2 = laplace_noise(1.0, &mut rng2);
        assert!((n1 - n2).abs() > f64::EPSILON);
    }

    #[test]
    fn laplace_noise_rng_state_changes() {
        // 呼び出し後にrng状態が変化する
        let mut rng = 100u64;
        let original = rng;
        let _ = laplace_noise(1.0, &mut rng);
        assert_ne!(rng, original);
    }

    #[test]
    fn laplace_noise_large_scale() {
        // 大きなscaleでもパニックしない
        let mut rng = 42u64;
        let noise = laplace_noise(1e10, &mut rng);
        assert!(noise.is_finite());
    }

    #[test]
    fn laplace_noise_small_scale() {
        // 小さなscaleではノイズが小さい
        let mut rng = 42u64;
        let noise = laplace_noise(1e-10, &mut rng);
        assert!(noise.abs() < 1.0);
    }

    #[test]
    fn laplace_noise_multiple_calls() {
        // 複数回呼び出しで異なる値
        let mut rng = 42u64;
        let n1 = laplace_noise(1.0, &mut rng);
        let n2 = laplace_noise(1.0, &mut rng);
        assert!((n1 - n2).abs() > f64::EPSILON);
    }

    #[test]
    fn laplace_noise_variance_increases_with_scale() {
        // scaleが大きいほど分散が大きい
        let mut rng1 = 42u64;
        let mut rng2 = 42u64;
        let mut var_small = 0.0;
        let mut var_large = 0.0;
        for _ in 0..500 {
            let n = laplace_noise(0.1, &mut rng1);
            var_small += n * n;
            let n = laplace_noise(10.0, &mut rng2);
            var_large += n * n;
        }
        assert!(var_large > var_small);
    }

    // -----------------------------------------------------------------------
    // uniform 関連テスト
    // -----------------------------------------------------------------------

    #[test]
    fn uniform_in_range() {
        // uniform()が[0, 1)に収まることを確認
        let mut rng = 42u64;
        for _ in 0..1000 {
            let u = uniform(&mut rng);
            assert!(u >= 0.0);
            assert!(u < 1.0);
        }
    }

    #[test]
    fn uniform_different_values() {
        // 複数回呼び出しで異なる値を生成
        let mut rng = 42u64;
        let u1 = uniform(&mut rng);
        let u2 = uniform(&mut rng);
        assert!((u1 - u2).abs() > f64::EPSILON);
    }

    #[test]
    fn uniform_zero_seed_handled() {
        // シード0でもxorshift64が0除算しない
        let mut rng = 0u64;
        let u = uniform(&mut rng);
        assert!(u >= 0.0);
        assert!(u < 1.0);
    }

    // -----------------------------------------------------------------------
    // dp_count 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn dp_count_zero() {
        // カウント0に対するDP
        let mut rng = 42u64;
        let noisy = dp_count(0, 1.0, &mut rng);
        assert!(noisy.abs() < 50.0);
    }

    #[test]
    fn dp_count_large_epsilon() {
        // ε大 → ノイズ小（精度高い）
        let mut rng = 42u64;
        let noisy = dp_count(100, 100.0, &mut rng);
        assert!((noisy - 100.0).abs() < 5.0);
    }

    #[test]
    fn dp_count_small_epsilon() {
        // ε小 → ノイズ大
        let mut rng = 42u64;
        let noisy = dp_count(100, 0.01, &mut rng);
        // ノイズが大きいのでゆるいアサーション
        assert!(noisy.is_finite());
    }

    #[test]
    fn dp_count_large_count() {
        // 大きなカウント値
        let mut rng = 42u64;
        let noisy = dp_count(1_000_000, 1.0, &mut rng);
        assert!((noisy - 1_000_000.0).abs() < 100.0);
    }

    #[test]
    fn dp_count_deterministic_with_same_seed() {
        // 同じシードなら同じ結果
        let mut rng1 = 42u64;
        let mut rng2 = 42u64;
        let n1 = dp_count(100, 1.0, &mut rng1);
        let n2 = dp_count(100, 1.0, &mut rng2);
        assert!((n1 - n2).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // dp_sum 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn dp_sum_zero() {
        // 合計0に対するDP
        let mut rng = 42u64;
        let noisy = dp_sum(0.0, 10.0, 1.0, &mut rng);
        assert!(noisy.abs() < 100.0);
    }

    #[test]
    fn dp_sum_negative() {
        // 負の合計値
        let mut rng = 42u64;
        let noisy = dp_sum(-500.0, 10.0, 1.0, &mut rng);
        assert!((noisy - (-500.0)).abs() < 100.0);
    }

    #[test]
    fn dp_sum_sensitivity_zero() {
        // sensitivity=0 → ノイズなし（scale=0）
        let mut rng = 42u64;
        let noisy = dp_sum(42.0, 0.0, 1.0, &mut rng);
        assert!((noisy - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn dp_sum_large_epsilon() {
        // ε大 → ノイズ小
        let mut rng = 42u64;
        let noisy = dp_sum(1000.0, 10.0, 100.0, &mut rng);
        assert!((noisy - 1000.0).abs() < 10.0);
    }

    #[test]
    fn dp_sum_deterministic_with_same_seed() {
        // 同じシードなら同じ結果
        let mut rng1 = 42u64;
        let mut rng2 = 42u64;
        let n1 = dp_sum(100.0, 5.0, 1.0, &mut rng1);
        let n2 = dp_sum(100.0, 5.0, 1.0, &mut rng2);
        assert!((n1 - n2).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // generalize_numeric 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn generalize_numeric_negative() {
        // 負の値
        let (lo, hi) = generalize_numeric(-15.0, 10.0);
        assert!((lo - (-20.0)).abs() < 0.01);
        assert!((hi - (-10.0)).abs() < 0.01);
    }

    #[test]
    fn generalize_numeric_zero() {
        // 値が0
        let (lo, hi) = generalize_numeric(0.0, 10.0);
        assert!(lo.abs() < 0.01);
        assert!((hi - 10.0).abs() < 0.01);
    }

    #[test]
    fn generalize_numeric_on_boundary() {
        // ちょうどバケット境界
        let (lo, hi) = generalize_numeric(20.0, 10.0);
        assert!((lo - 20.0).abs() < 0.01);
        assert!((hi - 30.0).abs() < 0.01);
    }

    #[test]
    fn generalize_numeric_small_bucket() {
        // 小さなバケット
        let (lo, hi) = generalize_numeric(2.7, 0.5);
        assert!((lo - 2.5).abs() < 0.01);
        assert!((hi - 3.0).abs() < 0.01);
    }

    #[test]
    fn generalize_numeric_large_value() {
        // 大きな値
        let (lo, hi) = generalize_numeric(12345.0, 100.0);
        assert!((lo - 12300.0).abs() < 0.01);
        assert!((hi - 12400.0).abs() < 0.01);
    }

    #[test]
    fn generalize_numeric_fractional() {
        // 小数値
        let (lo, hi) = generalize_numeric(3.15, 1.0);
        assert!((lo - 3.0).abs() < 0.01);
        assert!((hi - 4.0).abs() < 0.01);
    }

    #[test]
    fn generalize_numeric_bucket_one() {
        // バケットサイズ1
        let (lo, hi) = generalize_numeric(7.5, 1.0);
        assert!((lo - 7.0).abs() < 0.01);
        assert!((hi - 8.0).abs() < 0.01);
    }

    #[test]
    fn generalize_numeric_negative_fractional() {
        // 負の小数値
        let (lo, hi) = generalize_numeric(-3.7, 2.0);
        assert!((lo - (-4.0)).abs() < 0.01);
        assert!((hi - (-2.0)).abs() < 0.01);
    }

    #[test]
    fn generalize_numeric_consistency() {
        // 同じバケット内の2値は同じ範囲
        let (lo1, hi1) = generalize_numeric(15.1, 10.0);
        let (lo2, hi2) = generalize_numeric(19.9, 10.0);
        assert!((lo1 - lo2).abs() < 0.01);
        assert!((hi1 - hi2).abs() < 0.01);
    }

    // -----------------------------------------------------------------------
    // ln_approx 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn ln_approx_one() {
        // ln(1) = 0
        let v = ln_approx(1.0);
        assert!(v.abs() < 0.001);
    }

    #[test]
    fn ln_approx_zero() {
        // ln(0) は大きな負の値
        let v = ln_approx(0.0);
        assert!(v < -10.0);
    }

    #[test]
    fn ln_approx_negative() {
        // 負の値は大きな負を返す
        let v = ln_approx(-1.0);
        assert!(v < -10.0);
    }

    #[test]
    fn ln_approx_two() {
        // ln(2) ≈ 0.693
        let v = ln_approx(2.0);
        assert!((v - core::f64::consts::LN_2).abs() < 0.01);
    }

    #[test]
    fn ln_approx_small_positive() {
        // 小さい正の値
        let v = ln_approx(0.1);
        // ln(0.1) ≈ -2.302
        // ln(0.1) ≈ -ln(10) ≈ -2.3026
        assert!((v + core::f64::consts::LN_10).abs() < 0.1);
    }

    // -----------------------------------------------------------------------
    // floor_f64 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn floor_positive_fraction() {
        assert!((floor_f64(3.7) - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn floor_negative_fraction() {
        // floor(-3.7) = -4.0
        assert!((floor_f64(-3.7) - (-4.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn floor_positive_integer() {
        assert!((floor_f64(5.0) - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn floor_negative_integer() {
        assert!((floor_f64(-5.0) - (-5.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn floor_zero() {
        assert!((floor_f64(0.0)).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // DataShieldError 追加テスト
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_insufficient_anonymity() {
        let err = DataShieldError::InsufficientAnonymity;
        let msg = alloc::format!("{err}");
        assert_eq!(msg, "insufficient anonymity");
    }

    #[test]
    fn error_display_invalid_epsilon() {
        let err = DataShieldError::InvalidEpsilon;
        let msg = alloc::format!("{err}");
        assert_eq!(msg, "invalid epsilon");
    }

    #[test]
    fn error_clone() {
        let err = DataShieldError::InsufficientAnonymity;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn error_partial_eq() {
        assert_eq!(
            DataShieldError::InsufficientAnonymity,
            DataShieldError::InsufficientAnonymity
        );
        assert_ne!(
            DataShieldError::InsufficientAnonymity,
            DataShieldError::InvalidEpsilon
        );
    }

    #[test]
    fn error_debug() {
        let err = DataShieldError::InvalidEpsilon;
        let debug = alloc::format!("{err:?}");
        assert!(debug.contains("InvalidEpsilon"));
    }

    // -----------------------------------------------------------------------
    // xorshift64 間接テスト
    // -----------------------------------------------------------------------

    #[test]
    fn xorshift64_via_uniform_produces_different_values() {
        // 連続呼び出しで異なる値を生成
        let mut rng = 1u64;
        let mut values = Vec::new();
        for _ in 0..10 {
            values.push(uniform(&mut rng));
        }
        // 全値がユニークであることを確認
        for i in 0..values.len() {
            for j in (i + 1)..values.len() {
                assert!((values[i] - values[j]).abs() > f64::EPSILON);
            }
        }
    }

    #[test]
    fn xorshift64_zero_seed_recovery() {
        // シード0はxorshift64内部で1に置換される
        let mut rng = 0u64;
        let _ = uniform(&mut rng);
        // 状態が0でないことを確認
        assert_ne!(rng, 0);
    }

    // -----------------------------------------------------------------------
    // 統合テスト: マスキングの組み合わせ
    // -----------------------------------------------------------------------

    #[test]
    fn mask_then_check_length_preserved() {
        // マスキング後も文字数が保存される
        let original = "Hello, World!";
        let masked = mask_string(original, 3);
        assert_eq!(original.chars().count(), masked.chars().count());
    }

    #[test]
    fn mask_email_preserves_domain() {
        // メールマスキング後もドメイン部分が完全に保存される
        let email = "test@example.com";
        let masked = mask_email(email);
        assert!(masked.ends_with("@example.com"));
    }

    #[test]
    fn mask_card_last_four_preserved() {
        // カードマスキング後も末尾4桁が保存される
        let card = "4111111111111111";
        let masked = mask_card(card);
        assert!(masked.ends_with("1111"));
        assert_eq!(masked.len(), 16);
    }

    // -----------------------------------------------------------------------
    // 統合テスト: k-匿名性 + 等価クラス
    // -----------------------------------------------------------------------

    #[test]
    fn equivalence_classes_k_anonymity_integration() {
        // 等価クラスを計算してからk-匿名性チェック
        let ids = vec![1, 1, 1, 2, 2, 2, 3, 3, 3];
        let classes = compute_equivalence_classes(&ids);
        assert!(check_k_anonymity(&classes, 3));
        assert!(!check_k_anonymity(&classes, 4));
    }

    #[test]
    fn equivalence_classes_insufficient_anonymity() {
        // 不十分な匿名性を検出
        let ids = vec![1, 1, 2, 3, 3, 3];
        let classes = compute_equivalence_classes(&ids);
        // classes = [2, 1, 3] → k=2で失敗（1がある）
        assert!(!check_k_anonymity(&classes, 2));
    }

    // -----------------------------------------------------------------------
    // 統合テスト: DP + 統計的性質
    // -----------------------------------------------------------------------

    #[test]
    fn dp_count_mean_converges() {
        // 多数のDP countの平均が真値に収束
        let mut rng = 999u64;
        let true_count = 100u64;
        let mut total = 0.0;
        let n = 1000;
        for _ in 0..n {
            total += dp_count(true_count, 1.0, &mut rng);
        }
        let mean = total / f64::from(n);
        assert!((mean - 100.0).abs() < 5.0);
    }

    #[test]
    fn dp_sum_mean_converges() {
        // 多数のDP sumの平均が真値に収束
        let mut rng = 777u64;
        let true_sum = 250.0;
        let mut total = 0.0;
        let n = 1000;
        for _ in 0..n {
            total += dp_sum(true_sum, 5.0, 1.0, &mut rng);
        }
        let mean = total / f64::from(n);
        assert!((mean - 250.0).abs() < 5.0);
    }
}
