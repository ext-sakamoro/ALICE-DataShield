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

## License

AGPL-3.0-or-later
