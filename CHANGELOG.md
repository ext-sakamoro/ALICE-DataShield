# Changelog

All notable changes to ALICE-DataShield are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

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
