# ALICE DataShield

Data Security Posture Management (DSPM) SaaS with automated sensitive data discovery.

## Architecture

```
Frontend (Next.js 15) → API Gateway (Rust/Axum) → Data Scanner
                                                 → Classification Engine
                                                 → Posture Scorer
```

## Features

| Feature | Description |
|---------|------------|
| **Data Scanning** | Scan S3, databases, file systems for sensitive data |
| **Classification** | PII, PCI, PHI auto-detection with confidence scoring |
| **Posture Scoring** | Real-time security posture with risk-level assessment |
| **Encryption Audit** | Verify encryption at rest/transit with compliance mapping |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/datashield/scan` | Scan data source |
| POST | `/api/v1/datashield/posture` | Check security posture |
| POST | `/api/v1/datashield/encrypt-audit` | Encryption audit |
| GET | `/api/v1/datashield/stats` | Service statistics |

## Quick Start

```bash
docker compose up -d
# API: http://localhost:8081
# Frontend: http://localhost:3000
```

## Differential privacy

The noise comes from [`alice-crypto`](https://github.com/ext-sakamoro/ALICE-Crypto)'s
`dp` module, re-exported here as `differential_privacy`:

```rust
use alice_datashield::differential_privacy::{dp_count, SecureRng};

let mut rng = SecureRng::from_key(key_from_your_key_store);
let noisy: i64 = dp_count(1_000, 1.0, &mut rng)?;   // count + discrete Laplace
```

Reproducibility and privacy are not in conflict here because the determinism is
anchored to a **secret key** rather than to a clock: the same key gives the same
noise (replay, audit, tests), and without the key the noise can be neither
predicted nor reproduced — so it cannot be subtracted back out.

This crate used to carry its own ChaCha20 block function, CSPRNG and inverse
transform. They were removed in favour of one implementation upstream: the same
law existing twice is the same law getting fixed once.

⚠️ `dp_count` / `dp_sum` / `DpNoise` take ε (and the sensitivity Δ) and derive
the noise themselves. An ε that is accepted and then ignored is worse than no ε
at all, and passing a scale in is how that happens.

The noise is sampled with integer arithmetic only and in constant time
(alice-crypto 0.3): no floating-point `ln` or `exp`, whose low bits leak the
uniform draw (Mironov 2012), and no sampling time that grows with the noise.
Counts get discrete Laplace noise; real values are rounded to a power-of-two
lattice of `2^-20 Δ` first. The guarantee is `(ε_eff, δ)`-differential
privacy with `ε_eff ≤ ε · (1 + 2^-20)` and `δ = (1 + e^ε_eff) · 2^-103`; the
upstream module doc gives each term.

## License

**AGPL-3.0-or-later OR LicenseRef-Commercial** (dual-licensed) — see
[LICENSE-AGPL](LICENSE-AGPL) and [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).

Running this service for yourself costs nothing. Offering the same service to
others over a network is what the AGPL asks you to publish your changes for; if
that does not suit, the commercial option exists. Commercial enquiries:
contact@extoria.co.jp
