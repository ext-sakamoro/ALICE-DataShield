# Changelog

All notable changes to ALICE-DataShield are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- `alice-crypto` を 0.3 から 0.4 に上げた 0.4 で足された `dp_int` (整数の値の離散 Laplace) / `randomized_response` / `bernoulli_ratio` を `differential_privacy` から再 export し、`DpError::InvalidProbability` も届く 0.3 の `SecureRng` は keystream の 2^32 − 1 block 目 (約 256 GiB) で panic したが、0.4 で直っている 試験 `tests/dp_bridge.rs` に 3 つが本 crate の path から呼べて noise が乗ることを足した

## [0.2.0] — 2026-10-10

### 移行 (0.1.x の `differential_privacy` から)

- `dp_count(count, ε, rng)` の戻り値は `f64` から `i64` に (noise は整数) 浮動小数点として比べていた箇所は整数の比較にする
- `DpNoise::with_key(scale, key)` / `try_with_key(scale, key)` は `(sensitivity, epsilon, key)` に 旧 `scale` は `sensitivity / epsilon` なので、`with_key(b, key)` は `with_key(b, 1.0, key)` で同じ尺度になる `try_from_entropy(scale)` も `(sensitivity, epsilon)` に
- `DpNoise::laplace()` (noise だけを返す) は無くなった 値を受けて格子に丸めてから noise を足す `DpNoise::privatize(x)` を使う
- `DpNoise::scale()` は `sensitivity()` / `epsilon()` / `lattice()` / `effective_epsilon()` に
- 不正な引数の `DpError` に `EpsilonOutOfRange` / `CountOutOfRange` / `ValueOutOfRange` が加わった

### Changed

- CI: repo 直下の library crate (`differential_privacy` と integration test) を ubuntu / macos / windows で fmt・clippy・test する job `root-crate` を足した (従来の CI は services の check / clippy だけで、この crate の試験は CI で 1 本も走っていなかった) test の件数は target (lib・各 integration test・doc test) ごとに `scripts/test_counts.py` が数え、0 本の target があれば失敗する (合計だけだと 1 つの target が 0 本でも通る、意図して 0 本の target は `scripts/test-count-allowlist.txt` に理由つきで載せる、試験は `scripts/test_test_counts.py`) preflight にも同じ step を足した
- CI: `ci.yml` が `ci/**` branch の push と手動実行 (`workflow_dispatch`) でも走る (main に fast-forward する前に同じ検査を branch で回すため)
- **`alice-crypto` を 0.3 に上げた (差分プライバシーの noise)** 0.2 の noise は浮動小数点の逆関数法で、結果の下位 bit が一様値を漏らした (Mironov 2012) 0.3 は整数演算だけの離散 Laplace を定数時間で標本化する (count はそのまま、実数は格子 `2^-20 Δ` に丸めてから) 保証は `(ε_eff, δ)`-差分プライバシーで `ε_eff ≤ ε · (1 + 2^-20)`、`δ = (1 + e^ε_eff) · 2^-103` 再公開している `differential_privacy` の型が変わる: `dp_count` は `i64` を返す / `DpNoise::with_key` と `try_with_key` は `(sensitivity, epsilon, key)` を受ける / `DpNoise::laplace()` は無くなり、値を格子に丸めてから noise を足す `privatize(x)` を使う / `DpNoise::scale()` は `sensitivity()` / `epsilon()` / `lattice()` / `effective_epsilon()` に 移行手順は alice-crypto の CHANGELOG 0.3.0
- **The differential-privacy noise source moved upstream to `alice-crypto`'s
  `dp` module** and is re-exported here as `differential_privacy`, so every
  name callers use is unchanged. This crate's own `chacha20`, `csprng` and
  Laplace implementation are gone. ⚠️ The reason is not tidiness: the same law
  existed in three places independently, and when the defect below was fixed,
  only this copy got the fix. One implementation is one thing to fix.
- **License: `LicenseRef-Proprietary` → `AGPL-3.0-or-later OR
  LicenseRef-Commercial`** (dual-licensed). ⚠️ The previous choice rested on
  circular reasoning: the commit that set the条文 to proprietary gave its reason
  as "the repository is unpublished and private", and no reason for the
  repository being private was recorded. The条文 before that was AGPL-3.0, which
  is the default of the template this service came from, and two sibling
  services from the same template are public. AGPL also fits the shape of a
  hosted service — self-hosting is free, offering the same service to others
  carries the publication obligation — and the commercial option covers the rest.
  `publish = false` stays: this is a service, not a library.
- README's license section said `AGPL-3.0-or-later` the whole time the manifest
  said proprietary. Both now say the same thing.

### Security

- (2026-10-09, in the commit that preceded this one) **The noise was predictable
  and its distribution was wrong.** `xorshift64` seeded from the system clock
  with the state handed back to the caller: the clock is guessable, and
  xorshift is F2-linear so 64 output bits are enough to solve for the state by
  linear algebra — past and future noise reconstructable without brute force.
  `ln` was a 20-term series that returned a magic `-100.0` outside its domain,
  which `u → 0` reached in practice. Both are fixed in the upstream module,
  whose oracle pins mean 0 / variance 2b² and the RFC 8439 keystream.
