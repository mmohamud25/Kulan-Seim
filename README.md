# KULAN THREAT INTELLIGENCE PLATFORM

**A SOC-grade threat intelligence aggregation and scoring platform built in Python + Flask.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=flat-square&logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

Kulan TIP ingests live threat intelligence from public feeds, normalizes IOCs (Indicators of Compromise) into a local SQLite database, calculates a proprietary threat score for each indicator, and exposes the data via a REST API — powering a real-time SOC operations dashboard.

Built to demonstrate practical skills in threat intelligence workflows, data normalization, risk scoring, and defensive security operations — directly applicable to SOC Analyst and IT Security Analyst roles.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FEED SOURCES                         │
│  CISA KEV (public) · AlienVault OTX · AbuseIPDB        │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                  ingest.py                              │
│  Fetches · Normalizes · Deduplicates IOCs               │
│  Handles offline fallback gracefully                    │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   score.py                              │
│  Kulan Threat Score Model v1.0                          │
│  Source Reliability + Severity + Recency +              │
│  Category Weight + Ransomware Bonus → 0–100 score       │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                    db.py                                │
│  SQLite: iocs · cisa_kev · alerts · ingest_log          │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                    app.py                               │
│  Flask REST API — 7 endpoints                           │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              Dashboard (HTML/CSS/JS)                    │
│  KPI cards · IOC feed table · Alert queue               │
│  Risk score gauge · Attack category charts              │
└─────────────────────────────────────────────────────────┘
```

---

## Features

- **Multi-feed ingestion** — CISA KEV (no key), AlienVault OTX, AbuseIPDB
- **Proprietary threat scoring** — 5-factor model, 0–100 scale (see METHODOLOGY.md)
- **SQLite persistence** — normalized schema with audit log on every sync
- **REST API** — 7 endpoints powering the live dashboard
- **SOC-style alert queue** — auto-generates alerts for ransomware-linked KEV entries
- **Graceful offline mode** — runs with demo data when feeds are unavailable
- **CLI flags** — `--feed kev|otx|all`, `--dry-run` for safe testing

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/kulan-tip.git
cd kulan-tip

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Configure API keys
cp .env.example .env
# Edit .env with your OTX and AbuseIPDB keys

# 4. Run — auto-initializes DB and syncs feeds on first launch
python app.py
```

Visit `http://localhost:5000` for the dashboard, or hit the API directly:

```
http://localhost:5000/api/metrics
http://localhost:5000/api/iocs
http://localhost:5000/api/kev
http://localhost:5000/api/alerts
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Platform health check |
| GET | `/api/metrics` | KPI dashboard data (risk score, counts) |
| GET | `/api/iocs` | IOC feed with optional filters |
| GET | `/api/iocs/stats` | Severity / category breakdown |
| GET | `/api/kev` | CISA KEV catalog entries |
| GET | `/api/alerts` | SOC alert queue |
| GET | `/api/ingest/run` | Trigger manual feed sync |

**IOC filter params:** `?severity=critical`, `?category=ransomware`, `?status=active`, `?limit=50`

---

## Project Structure

```
kulan-tip/
├── app.py            # Flask REST API
├── db.py             # Database schema and query helpers
├── score.py          # Kulan Threat Score Engine
├── ingest.py         # Multi-feed ingestion engine
├── requirements.txt
├── .env.example      # API key template
├── .gitignore
├── METHODOLOGY.md    # Threat scoring model documentation
├── data/
│   └── kulan_tip.db  # SQLite database (git-ignored)
└── dashboard/
    └── index.html    # SOC operations dashboard
```

---

## Supported Feed Sources

| Feed | Auth Required | IOC Types | Notes |
|------|--------------|-----------|-------|
| CISA KEV | None | CVE | US gov confirmed exploited vulns |
| AlienVault OTX | Free API key | IP, Domain, Hash, URL | Community threat intel |
| AbuseIPDB | Free API key | IP | Crowd-reported abusive IPs |

---

## Methodology

The Kulan Threat Score Model v1.0 is documented in full in [METHODOLOGY.md](./METHODOLOGY.md).

Short version: each IOC is scored 0–100 across five dimensions — source authority, severity, recency, threat category, and ransomware campaign linkage. The score drives prioritization in the SOC dashboard and alert generation logic.

---

## SOC Workflow Mapping

This platform replicates four core SOC Tier 1 analyst workflows:

1. **Feed ingestion** — pulling and normalizing threat intelligence from multiple sources
2. **IOC enrichment** — tagging each indicator with context (type, category, source, score)
3. **Alert triage** — auto-generating prioritized alerts for high-risk indicators
4. **Risk quantification** — aggregating IOC data into an environment-level risk score

---

## Roadmap

- [ ] Phase 3 — Live CISA KEV feed (when network available)
- [ ] Phase 4 — Log ingestion simulator (fake SIEM log stream)
- [ ] Phase 5 — Incident response runbook generator (per IOC type)
- [ ] Phase 6 — MITRE ATT&CK technique tagging per IOC

---

## Author

**Mohamed Mohamud**
Security professional | Cybersecurity educator | MS Computer Science candidate
Columbus, OH · [kulaninstitute.org](https://kulaninstitute.org)

CompTIA Security+ SY0-701 (in progress) · ISC2 CC (in progress)
Google Data Analytics · IBM Data Analyst certifications

---

## License

MIT License — see LICENSE for details.
