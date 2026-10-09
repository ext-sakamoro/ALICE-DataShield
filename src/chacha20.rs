//! ChaCha20 (RFC 8439) の block 関数 — 差分プライバシーの noise 源
//!
//! # なぜ CSPRNG が要るのか
//!
//! 差分プライバシーは「noise を外した値を攻撃者が復元できない」ことに依る
//! noise 生成に線形合同法や xorshift を使うと、⚠️ **出力の数語から内部状態が解けて
//! 過去・未来の noise が全部再現できる** (xorshift は F2 線形なので、64 bit 分の
//! 出力から線形代数で状態が求まる) 時刻を seed にすると、⚠️ **おおよその時刻を知る
//! 攻撃者が候補を総当たりできる** (ns 単位でも秒が分かれば 10^9 通り)
//!
//! どちらも「noise を完全に再現して引き去る」攻撃を通すので、ε の主張が成立しない
//!
//! # 再現性と秘匿の両立
//!
//! ⚠️ この 2 つは「決定論の基準を何に置くか」で両立する
//!
//! - **公開値 (時刻・連番) を基準にすると両立しない** — 攻撃者も同じ値を推測できる
//! - **秘密の鍵を基準にすると両立する** — 同じ鍵なら同じ noise 列が出る (replay と
//!   試験で再現できる)、鍵を知らない側からは予測も再現もできない
//!
//! 本 module は鍵 (32 byte) と block counter から keystream を作る 鍵の出所は
//! 呼び出し側が決める ([`crate::privacy::SecureRng::from_key`] / OS entropy からの
//! [`crate::privacy::SecureRng::try_from_entropy`])
//!
//! # 実装の範囲
//!
//! block 関数 (20 round) だけを持つ 暗号化 (平文との XOR)・Poly1305・AEAD は持たない
//! 固定の置換なので RFC 8439 の test vector で正しさを機械的に固定できる
//! (§ 2.1.1 quarter round / § 2.3.2 の 64 byte keystream、`tests/chacha20_rfc8439.rs`)

/// ChaCha20 の初期 state の定数 ("expand 32-byte k" の little-endian 4 語)
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// RFC 8439 § 2.1 quarter round
///
/// 4 語を混ぜる 加算は wrapping、回転は左回転
#[inline]
const fn quarter_round(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);

    (a, b, c, d)
}

/// state の 4 語に quarter round を適用する
///
/// 添字は RFC 8439 § 2.3 の state 配列の位置 (column round / diagonal round)
#[inline]
#[allow(clippy::many_single_char_names)]
const fn qr(state: &mut [u32; 16], w0: usize, w1: usize, w2: usize, w3: usize) {
    let (a, b, c, d) = quarter_round(state[w0], state[w1], state[w2], state[w3]);
    state[w0] = a;
    state[w1] = b;
    state[w2] = c;
    state[w3] = d;
}

/// RFC 8439 § 2.3 の block 関数
///
/// `key` (32 byte) / `counter` (32 bit の block 番号) / `nonce` (12 byte) から
/// 64 byte の keystream block を作る
///
/// state の並びは RFC どおり: 定数 4 語 ‖ 鍵 8 語 ‖ counter 1 語 ‖ nonce 3 語
/// (すべて little-endian) 20 round (column round と diagonal round を 10 回) の後、
/// 初期 state を wrapping 加算して little-endian で直列化する
#[must_use]
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[0..4].copy_from_slice(&CONSTANTS);
    for (w, chunk) in init[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    init[12] = counter;
    for (w, chunk) in init[13..16].iter_mut().zip(nonce.chunks_exact(4)) {
        *w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    let mut s = init;
    for _ in 0..10 {
        // column round
        qr(&mut s, 0, 4, 8, 12);
        qr(&mut s, 1, 5, 9, 13);
        qr(&mut s, 2, 6, 10, 14);
        qr(&mut s, 3, 7, 11, 15);
        // diagonal round
        qr(&mut s, 0, 5, 10, 15);
        qr(&mut s, 1, 6, 11, 12);
        qr(&mut s, 2, 7, 8, 13);
        qr(&mut s, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for (i, (word, start)) in s.iter().zip(init.iter()).enumerate() {
        let v = word.wrapping_add(*start);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{chacha20_block, quarter_round};

    /// RFC 8439 § 2.1.1 の quarter round test vector
    ///
    /// 期待値は RFC の本文から転記 (実装の出力から書き起こしていない)
    #[test]
    fn quarter_round_matches_rfc_8439_section_2_1_1() {
        let got = quarter_round(0x1111_1111, 0x0102_0304, 0x9b8d_6f43, 0x0123_4567);
        assert_eq!(got, (0xea2a_92f4, 0xcb1c_f8ce, 0x4581_472e, 0x5881_c4bb));
    }

    #[test]
    fn the_nonce_changes_the_block() {
        let key = [0u8; 32];
        let a = chacha20_block(&key, 0, &[0u8; 12]);
        let mut nonce = [0u8; 12];
        nonce[11] = 1;
        let b = chacha20_block(&key, 0, &nonce);
        assert_ne!(a, b);
    }
}
