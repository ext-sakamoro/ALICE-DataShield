//! 差分プライバシーの noise 源 (ChaCha20 keystream)
//!
//! # 再現性と秘匿の両立
//!
//! ⚠️ この 2 つは「決定論の基準を何に置くか」で両立する
//!
//! - **公開値 (時刻・連番) を基準にすると両立しない** — 攻撃者も同じ値を推測できる
//! - **秘密の鍵を基準にすると両立する** — 同じ鍵なら同じ noise 列、鍵を知らない側からは
//!   予測も再現もできない
//!
//! 2026-10-09 まで本 crate は `xorshift64` + 呼び出し側が持ち回る 64 bit 状態だった
//! ⚠️ xorshift は F2 線形なので **出力 64 bit 分から内部状態が線形代数で解け、過去・未来の
//! noise 全部が再現できる** (鍵の総当たりすら要らない) noise を引き去られると ε の主張が
//! 成立しないので、CSPRNG に替えた

use crate::chacha20::chacha20_block;

/// OS の entropy が取れなかった
///
/// ⚠️ この error を時刻や固定値への fallback で潰してはいけない 推測できる値を鍵に
/// すると、noise を再現して引き去る攻撃が通る
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntropyError;

impl core::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "entropy source unavailable; pass a 32-byte key explicitly (never a time-derived seed)",
        )
    }
}

/// ChaCha20 keystream を 8 byte 単位で返す
#[derive(Clone, Debug)]
pub struct SecureRng {
    key: [u8; 32],
    /// 次に使う block 番号 下位 32 bit を RFC の counter、上位を nonce に入れる
    block: u64,
    buf: [u8; 64],
    pos: usize,
}

impl SecureRng {
    /// 鍵から作る (同じ鍵は同じ列)
    #[must_use]
    pub fn from_key(key: [u8; 32]) -> Self {
        let mut rng = Self {
            key,
            block: 0,
            buf: [0u8; 64],
            pos: 64,
        };
        rng.refill();
        rng
    }

    /// OS entropy から鍵を取る
    ///
    /// # Errors
    ///
    /// entropy source が使えない時 ⚠️ 呼び出し側は**失敗を時刻や固定値で埋めない**
    /// 鍵を用意できないなら noise を足さずに止める
    pub fn try_from_entropy() -> Result<Self, EntropyError> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| EntropyError)?;
        Ok(Self::from_key(key))
    }

    fn refill(&mut self) {
        // RFC 8439 の counter は 32 bit なので 64 bit の block 番号を
        // counter (下位) と nonce (上位) に分ける block は単調増加なので
        // 同じ鍵の中で (counter, nonce) の組は重複しない
        let counter = (self.block & 0xffff_ffff) as u32;
        let stream = (self.block >> 32) as u32;
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&stream.to_le_bytes());
        self.buf = chacha20_block(&self.key, counter, &nonce);
        self.pos = 0;
        self.block = self.block.wrapping_add(1);
    }

    /// 次の 8 byte
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        if self.pos + 8 > 64 {
            self.refill();
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        u64::from_le_bytes(b)
    }

    /// `(0, 1]` の一様 f64
    ///
    /// ⚠️ **0 を返さない** — `ln(0)` は `-inf` なので、逆関数法の入力として 0 が来ると
    /// noise が無限大になる 53 bit から作り、0 になった時だけ最小値に寄せる
    #[inline]
    pub fn next_f64_open01(&mut self) -> f64 {
        const SCALE: f64 = 1.0 / 9_007_199_254_740_992.0; // 2^-53
        let bits = self.next_u64() >> 11; // 53 bit
        #[allow(clippy::cast_precision_loss)]
        let u = (bits as f64) * SCALE;
        if u <= 0.0 {
            SCALE
        } else {
            u
        }
    }
}
