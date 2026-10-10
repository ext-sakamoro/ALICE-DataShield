//! 差分プライバシー — `alice-crypto` の `dp` module を再公開する
//!
//! # なぜここに実装を持たないのか
//!
//! 2026-10-09 まで本 crate は ChaCha20 の block 関数・CSPRNG・Laplace の逆関数法を
//! 自前で持っていた ⚠️ **同じ法則が ALICE-Crypto 側にもあり、写しが 2 つあると
//! 片方だけ直る事故が起きる** (現に差分プライバシーの noise は本 crate /
//! ALICE-Analytics / ALICE-Physics の 3 箇所に独立に存在し、本 crate だけが直った
//! 状態になっていた)
//!
//! ⚠️ 置き場を ALICE-Crypto にしたのは license の向きで決まる: 暗号 primitive の
//! 持ち主で、公開済かつ `AGPL-3.0-or-later OR LicenseRef-Commercial` なので、
//! AGPL 側の crate からも商用側の許諾でも引ける 新しい crate を作ると ChaCha20 の
//! 実装が 3 つ目になる
//!
//! # 使い方
//!
//! 名前は従来と同じ alice-crypto 0.3.0 で型が変わった点 (`dp_count` は `i64` を返す /
//! `DpNoise` は感度 Δ と ε を受け、値を格子に丸めてから noise を足す `privatize`
//! を持つ) は上流の CHANGELOG に移行手順がある
//!
//! ```
//! use alice_datashield::differential_privacy::{dp_count, SecureRng};
//!
//! let mut rng = SecureRng::from_key([7u8; 32]);
//! let noisy: i64 = dp_count(1_000, 1.0, &mut rng).expect("eps > 0");
//! assert!((noisy - 1_000).abs() < 1_000);
//! ```
//!
//! noise は浮動小数点の `ln` / `exp` を使わず整数演算だけで、定数時間で標本化する
//! (Mironov 2012 の下位 bit の漏れと、時間から noise の大きさが分かる経路の両方を
//! 塞ぐ) 保証は `(ε_eff, δ)`-差分プライバシーで、`ε_eff` と `δ` の式は上流の
//! module doc にある

pub use alice_crypto::dp::{
    bernoulli_ratio, dp_count, dp_int, dp_sum, randomized_response, DpError, DpNoise, EntropyError,
    SecureRng,
};
