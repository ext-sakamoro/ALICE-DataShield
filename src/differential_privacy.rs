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
//! 名前は従来と同じなので、呼び出し側の変更は要らない
//!
//! ```
//! use alice_datashield::differential_privacy::{dp_count, SecureRng};
//!
//! let mut rng = SecureRng::from_key([7u8; 32]);
//! let noisy = dp_count(1_000, 1.0, &mut rng).expect("eps > 0");
//! assert!(noisy.is_finite());
//! ```
//!
//! ⚠️ 残っている既知の限界は上流の module doc に書いてある (浮動小数点の逆関数法は
//! Mironov 2012 の LSB 攻撃の対象で、ε は理想的な実数演算での値)

pub use alice_crypto::dp::{
    dp_count, dp_sum, DpError, DpNoise, EntropyError, SecureRng,
};
