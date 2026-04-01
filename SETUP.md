# Setup Guide — Kulan Threat Intelligence Platform

---

## Local Setup (5 minutes)

### Prerequisites
- Python 3.10 or higher
- pip
- Git

### Steps

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/kulan-tip.git
cd kulan-tip

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API keys (optional — runs in demo mode without them)
cp .env.example .env
# Open .env and add your keys

# 4. Start the platform
python app.py
```

On first launch, `app.py` will:
- Initialize the SQLite database at `data/kulan_tip.db`
- Run an automatic feed sync (CISA KEV if network available, demo data if not)
- Start the Flask server at `http://localhost:5000`

---

## Getting Free API Keys

### AlienVault OTX (recommended)
1. Go to [otx.alienvault.com](https://otx.alienvault.com) and create a free account
2. Navigate to **Settings → API Integration**
3. Copy your OTX Key into `.env` as `OTX_API_KEY`
4. Subscribe to some threat pulses for better data volume

### AbuseIPDB
1. Go to [abuseipdb.com](https://www.abuseipdb.com) and create a free account
2. Navigate to **API** in the dashboard
3. Copy your key into `.env` as `ABUSEIPDB_KEY`
4. Free tier: 1,000 checks/day

---

## Running Feed Syncs Manually

```bash
# Sync all feeds
python ingest.py

# Sync only CISA KEV
python ingest.py --feed kev

# Preview without writing to DB
python ingest.py --dry-run

# Trigger via API (while app is running)
curl http://localhost:5000/api/ingest/run
curl http://localhost:5000/api/ingest/run?feed=kev
```

---

## Automating Feed Syncs (cron)

To keep your threat data fresh, schedule `ingest.py` to run periodically:

```bash
# Open crontab
crontab -e

# Add this line to sync every 6 hours
0 */6 * * * /usr/bin/python3 /path/to/kulan-tip/ingest.py >> /path/to/kulan-tip/logs/cron.log 2>&1
```

---

## API Quick Reference

```bash
# Health check
curl http://localhost:5000/api/health

# Dashboard metrics
curl http://localhost:5000/api/metrics

# All IOCs
curl http://localhost:5000/api/iocs

# Critical IOCs only
curl http://localhost:5000/api/iocs?severity=critical

# Ransomware-related IOCs
curl http://localhost:5000/api/iocs?category=ransomware

# CISA KEV — ransomware-linked only
curl http://localhost:5000/api/kev?ransomware=true

# Open alerts
curl http://localhost:5000/api/alerts

# IOC stats by category/severity
curl http://localhost:5000/api/iocs/stats
```

---

## Deploying the Dashboard to GitHub Pages

The `dashboard/index.html` is a standalone file — no server required for the frontend alone.

```bash
# If you only want to host the static dashboard:
# 1. Go to your GitHub repo → Settings → Pages
# 2. Set Source: Deploy from branch → main → /dashboard
# 3. Your dashboard will be live at:
#    https://YOUR_USERNAME.github.io/kulan-tip/
```

Note: The live API (`app.py`) requires a server. For full backend hosting, consider:
- **Railway** (free tier available)
- **Render** (free tier available)
- **PythonAnywhere** (free tier available)

---

## Running the Scoring Engine Standalone

```bash
# Run self-test with sample IOCs
python score.py

# Import in your own scripts
from score import calculate_threat_score, calculate_environment_risk

score = calculate_threat_score(
    source="CISA_KEV",
    severity="critical",
    category="ransomware",
    last_seen="2026-03-30T00:00:00",
    known_ransomware=True,
)
print(score)  # → 100.0
```

---

## Troubleshooting

**Database not found error**
```bash
mkdir -p data
python db.py  # re-initializes schema
```

**CISA KEV returns network error**
The platform automatically falls back to demo IOC data. Check your internet connection or firewall settings. The CISA KEV URL is: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**OTX returns 403**
Your API key may be invalid or expired. Generate a new one at otx.alienvault.com → Settings.

**Port 5000 already in use**
```bash
# Change port in app.py last line:
app.run(debug=True, host="0.0.0.0", port=5001)
```
