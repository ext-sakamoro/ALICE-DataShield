//! `ChaCha20` を RFC 8439 の test vector で固定する
//!
//! 期待値の出所: RFC 8439 (`https://www.rfc-editor.org/rfc/rfc8439.txt`)
//! - § 2.1.1 quarter round の 4 語
//! - § 2.3.2 block 関数 (key = 00..1f、nonce = 00:00:00:09:00:00:00:4a:00:00:00:00、
//!   block counter = 1) の 64 byte keystream
//!
//! ⚠️ この値を実装の出力から書き起こしてはいけない (実装が間違っていても緑になる)
//! 上記 RFC の本文を転記したものだけを置く
//!
//! 差分プライバシーの noise はこの keystream から取る 鍵が同じなら noise は
//! 再現でき (replay / 試験)、鍵を知らない側からは予測できない = 再現性と秘匿の両立

use alice_datashield::chacha20::chacha20_block;
use alice_datashield::csprng::SecureRng;

/// RFC 8439 § 2.3.2 の鍵 (0x00 から 0x1f の昇順)
fn rfc_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::try_from(i).expect("0..32 は u8");
    }
    k
}

/// RFC 8439 § 2.3.2 の nonce
const RFC_NONCE: [u8; 12] = [
    0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
];

/// RFC 8439 § 2.3.2 の 64 byte keystream (block counter = 1)
const RFC_KEYSTREAM: [u8; 64] = [
    0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
];

#[test]
fn the_block_function_matches_rfc_8439_section_2_3_2() {
    let got = chacha20_block(&rfc_key(), 1, &RFC_NONCE);
    assert_eq!(
        got, RFC_KEYSTREAM,
        "RFC 8439 § 2.3.2 の keystream と一致しない"
    );
}

#[test]
fn a_different_block_counter_gives_a_different_block() {
    let k = rfc_key();
    let one = chacha20_block(&k, 1, &RFC_NONCE);
    let two = chacha20_block(&k, 2, &RFC_NONCE);
    assert_ne!(one, two, "counter が違えば keystream も違う");
}

#[test]
fn one_bit_of_the_key_changes_the_whole_block() {
    let mut k = rfc_key();
    let base = chacha20_block(&k, 1, &RFC_NONCE);
    k[0] ^= 0x01;
    let flipped = chacha20_block(&k, 1, &RFC_NONCE);
    assert_ne!(base, flipped);
    // 雪崩効果: 64 byte のうち一致する byte は半分を大きく下回る
    let same = base
        .iter()
        .zip(flipped.iter())
        .filter(|(a, b)| a == b)
        .count();
    assert!(same < 8, "鍵 1 bit で {same} byte が不変 (雪崩していない)");
}

#[test]
fn the_same_key_reproduces_the_same_noise_stream() {
    // 再現性: 鍵が同じなら同じ列 (replay と試験がこれに依る)
    let key = [7u8; 32];
    let mut a = SecureRng::from_key(key);
    let mut b = SecureRng::from_key(key);
    let xs: Vec<u64> = (0..200).map(|_| a.next_u64()).collect();
    let ys: Vec<u64> = (0..200).map(|_| b.next_u64()).collect();
    assert_eq!(xs, ys, "同じ鍵は同じ列を返す");
    assert!(xs.len() == 200 && xs.iter().collect::<std::collections::BTreeSet<_>>().len() > 190);
}

#[test]
fn a_different_key_gives_an_unrelated_stream() {
    // 秘匿性の最低条件: 鍵が違えば列も違う (鍵を知らない側は再現できない)
    let mut a = SecureRng::from_key([7u8; 32]);
    let mut b = SecureRng::from_key({
        let mut k = [7u8; 32];
        k[31] ^= 0x80;
        k
    });
    let xs: Vec<u64> = (0..64).map(|_| a.next_u64()).collect();
    let ys: Vec<u64> = (0..64).map(|_| b.next_u64()).collect();
    assert_ne!(xs, ys);
    let shared = xs.iter().zip(ys.iter()).filter(|(x, y)| x == y).count();
    assert_eq!(shared, 0, "鍵が違うのに {shared} 語が一致した");
}

#[test]
fn the_stream_crosses_block_boundaries_without_repeating() {
    // 64 byte = 8 語ごとに block が変わる 境界で同じ block を出し直していないこと
    let mut rng = SecureRng::from_key([0x5au8; 32]);
    let xs: Vec<u64> = (0..32).map(|_| rng.next_u64()).collect();
    let first_block = &xs[0..8];
    let second_block = &xs[8..16];
    assert_ne!(first_block, second_block, "block 境界で列が繰り返している");
    let uniq = xs.iter().collect::<std::collections::BTreeSet<_>>().len();
    assert_eq!(uniq, xs.len(), "重複した語がある");
}

#[test]
fn uniform_doubles_stay_in_the_unit_interval() {
    let mut rng = SecureRng::from_key([1u8; 32]);
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    for _ in 0..10_000 {
        let u = rng.next_f64_open01();
        assert!(u > 0.0 && u <= 1.0, "u = {u} が (0,1] の外");
        min = min.min(u);
        max = max.max(u);
    }
    // 空振り防止: 定数を返していないこと
    assert!(max - min > 0.9, "範囲が {min}..{max} しかない");
}
