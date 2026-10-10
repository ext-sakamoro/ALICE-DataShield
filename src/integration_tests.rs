//! Integration tests.

#![allow(
    clippy::wildcard_imports,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use crate::differential_privacy::*;
use crate::errors::*;
use crate::generalization::*;
use crate::k_anonymity::*;
use crate::masking::*;
use alloc::vec;
use alloc::vec::Vec;

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
    let mut rng = crate::differential_privacy::SecureRng::from_key([42u8; 32]);
    let noisy = dp_count(1000, 1.0, &mut rng).expect("eps = 1 は有効");
    // Should be close to 1000 but not exact
    assert!((noisy - 1000).abs() < 50);
}

#[test]
fn dp_sum_noisy() {
    let mut rng = crate::differential_privacy::SecureRng::from_key([42u8; 32]);
    let noisy = dp_sum(500.0, 10.0, 1.0, &mut rng).expect("有効な引数");
    assert!((noisy - 500.0).abs() < 100.0);
}

#[test]
fn lattice_noise_distribution() {
    let mut noise = DpNoise::with_key(1.0, 1.0, [0x39u8; 32]);
    let mut sum = 0.0;
    let n = 1000;
    for _ in 0..n {
        sum += noise.privatize(0.0).expect("範囲内");
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
// 格子 noise (lattice_noise) 追加テスト
// -----------------------------------------------------------------------

#[test]
fn lattice_noise_scale_zero_is_refused() {
    // ⚠️ 旧実装は scale = 0 を「ノイズなし」として通していた
    //    scale = sensitivity / ε なので 0 は ε = ∞ (= 保護なし) を意味する
    //    黙って素通しにすると「DP を掛けたつもりで生値を出す」経路になる
    let got = DpNoise::try_with_key(0.0, 1.0, [42u8; 32]);
    assert!(
        matches!(got, Err(crate::differential_privacy::DpError::InvalidScale)),
        "scale = 0 を受理した"
    );
}

#[test]
fn lattice_noise_different_seeds() {
    // 異なるシードで異なるノイズ
    let n1 = DpNoise::with_key(1.0, 1.0, [1u8; 32])
        .privatize(0.0)
        .expect("範囲内");
    let n2 = DpNoise::with_key(1.0, 1.0, [2u8; 32])
        .privatize(0.0)
        .expect("範囲内");
    assert!((n1 - n2).abs() > f64::EPSILON);
}

#[test]
fn lattice_noise_advances_the_stream() {
    // 連続する 2 回が同じ値にならない (列が進んでいる = 同じ noise を使い回していない)
    let mut noise = DpNoise::with_key(1.0, 1.0, [100u8; 32]);
    let a = noise.privatize(0.0).expect("範囲内");
    let b = noise.privatize(0.0).expect("範囲内");
    assert_ne!(a.to_bits(), b.to_bits());
}

#[test]
fn lattice_noise_large_scale() {
    // 大きなscaleでもパニックしない
    let noise = DpNoise::with_key(1e10, 1.0, [42u8; 32])
        .privatize(0.0)
        .expect("範囲内");
    assert!(noise.is_finite());
}

#[test]
fn lattice_noise_small_scale() {
    // 小さな scale では noise も小さい
    let noise = DpNoise::with_key(1e-10, 1.0, [42u8; 32])
        .privatize(0.0)
        .expect("範囲内");
    assert!(noise.abs() < 1.0);
}

#[test]
fn lattice_noise_multiple_calls() {
    // 複数回呼び出しで異なる値 (同じ生成器から 2 回引く)
    let mut noise = DpNoise::with_key(1.0, 1.0, [42u8; 32]);
    let n1 = noise.privatize(0.0).expect("範囲内");
    let n2 = noise.privatize(0.0).expect("範囲内");
    assert!((n1 - n2).abs() > f64::EPSILON);
}

#[test]
fn lattice_noise_variance_increases_with_scale() {
    // scaleが大きいほど分散が大きい
    let mut small = DpNoise::with_key(0.1, 1.0, [42u8; 32]);
    let mut large = DpNoise::with_key(10.0, 1.0, [42u8; 32]);
    let mut var_small = 0.0;
    let mut var_large = 0.0;
    for _ in 0..500 {
        let n = small.privatize(0.0).expect("範囲内");
        var_small += n * n;
        let n = large.privatize(0.0).expect("範囲内");
        var_large += n * n;
    }
    // scale 100 倍なら分散は 10^4 倍 (2b²) 桁で確認する
    assert!(
        var_large > var_small * 1_000.0,
        "scale 0.1 の分散 {var_small} に対して scale 10 が {var_large} しかない"
    );
}

// -----------------------------------------------------------------------
// uniform 関連テスト
// -----------------------------------------------------------------------

#[test]
fn uniform_is_in_the_open_unit_interval() {
    // ⚠️ 範囲は (0, 1] — 0 を返さないことが要件 (逆関数法で ln(0) = -inf を踏むため)
    //    旧実装は [0, 1) で、0 が出ると noise が -inf になりえた
    let mut rng = crate::differential_privacy::SecureRng::from_key([42u8; 32]);
    for _ in 0..10_000 {
        let u = rng.next_f64_open01();
        assert!(u > 0.0, "0 が返った (ln(0) = -inf を踏む)");
        assert!(u <= 1.0, "1 を超えた: {u}");
    }
}

#[test]
fn uniform_advances_the_stream() {
    let mut rng = crate::differential_privacy::SecureRng::from_key([42u8; 32]);
    let u1 = rng.next_f64_open01();
    let u2 = rng.next_f64_open01();
    assert!((u1 - u2).abs() > f64::EPSILON);
}

#[test]
fn an_all_zero_key_still_produces_a_usable_stream() {
    // ⚠️ 全 0 の鍵は「弱い鍵」だが ChaCha20 は状態が縮退しない
    //    (xorshift は 0 状態で固定点になるので旧実装は特別扱いが要った)
    let mut rng = crate::differential_privacy::SecureRng::from_key([0u8; 32]);
    let xs: Vec<f64> = (0..64).map(|_| rng.next_f64_open01()).collect();
    assert!(xs.iter().all(|&u| u > 0.0 && u <= 1.0));
    assert!(
        xs.windows(2).any(|w| (w[0] - w[1]).abs() > f64::EPSILON),
        "列が進んでいない"
    );
}

// -----------------------------------------------------------------------
// dp_count 追加テスト
// -----------------------------------------------------------------------

#[test]
fn dp_count_deterministic_with_same_seed() {
    // 同じ鍵なら同じ結果 (決定論の基準は seed でなく 32 byte の秘密鍵)
    let mut rng1 = crate::differential_privacy::SecureRng::from_key([42u8; 32]);
    let mut rng2 = crate::differential_privacy::SecureRng::from_key([42u8; 32]);
    let n1 = dp_count(100, 1.0, &mut rng1).expect("有効な ε");
    let n2 = dp_count(100, 1.0, &mut rng2).expect("有効な ε");
    assert_eq!(n1, n2);
}

// -----------------------------------------------------------------------
// dp_sum 追加テスト
// -----------------------------------------------------------------------

#[test]
fn dp_sum_deterministic_with_same_seed() {
    // 同じシードなら同じ結果
    let mut rng1 = crate::differential_privacy::SecureRng::from_key([42u8; 32]);
    let mut rng2 = crate::differential_privacy::SecureRng::from_key([42u8; 32]);
    let n1 = dp_sum(100.0, 5.0, 1.0, &mut rng1).expect("有効な引数");
    let n2 = dp_sum(100.0, 5.0, 1.0, &mut rng2).expect("有効な引数");
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

// ln_approx は 2026-10-09 に削除した (自前の 20 項級数 + 定義域外で -100.0 を返す
// magic 値だった) 正典は alice-det-math の ln64 で、1 ulp まで det-math 側の試験が
// 固定している ここでは合成された分布 (tests/dp_noise_oracle.rs の平均 0 / 分散 2b²) で
// 見る ⚠️ 定義域外は呼ばない: u は (0, 1] なので ln は常に有限

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
