"""
score.py — Kulan Threat Intelligence Platform
Threat Scoring Engine: assigns a 0–100 risk score to each IOC.

Scoring Philosophy (KULAN THREAT SCORE MODEL v1.0):
────────────────────────────────────────────────────
Score = Source Reliability (25pts)
      + Severity Mapping (30pts)
      + Recency Decay (20pts)
      + Category Weight (15pts)
      + Ransomware Bonus (10pts)

This model is intentionally documented so it can be explained
in interviews and adapted for real enterprise environments.

Author: Mohamed Mohamud
"""

from datetime import datetime, timezone


# ─── WEIGHT TABLES ────────────────────────────────────────────────────────────

# Source reliability: higher = more authoritative
SOURCE_WEIGHTS = {
    "CISA_KEV":   25,   # US gov mandated exploited vulns — highest authority
    "OTX":        20,   # AlienVault Open Threat Exchange — crowd-sourced, trusted
    "AbuseIPDB":  17,   # Community IP reputation — good signal, higher noise
    "OSINT":      12,   # Open-source intel — variable quality
    "MANUAL":     15,   # Analyst-added — trusted but limited scale
}

# Severity → base score contribution
SEVERITY_SCORES = {
    "critical": 30,
    "high":     22,
    "medium":   14,
    "low":       6,
    "unknown":   3,
}

# Category risk weight
CATEGORY_WEIGHTS = {
    "ransomware":  15,   # Direct financial/operational impact
    "exploit":     14,   # Active exploitation of vulnerability
    "malware":     13,   # Malicious code delivery
    "c2":          12,   # Command & control infrastructure
    "phishing":    10,   # Social engineering / credential theft
    "brute-force":  7,   # Credential attacks
    "scanner":      4,   # Recon activity — lower urgency
    "unknown":      3,
}


# ─── RECENCY DECAY ────────────────────────────────────────────────────────────

def recency_score(last_seen_iso: str) -> float:
    """
    Score 0–20 based on how recently the IOC was observed.
    Fresh IOCs (< 1 day) score 20. Score decays to 0 after 30 days.

    Decay curve: linear from day 0 (20pts) to day 30 (0pts).
    After 30 days the IOC likely needs revalidation, so we cap at 2pts minimum.
    """
    if not last_seen_iso:
        return 5.0  # Unknown recency — partial credit

    try:
        last_seen = datetime.fromisoformat(last_seen_iso)
        # Make timezone-aware if naive
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - last_seen).total_seconds() / 86400

        if age_days < 0:
            age_days = 0

        if age_days > 30:
            return 2.0  # Stale but still on record

        # Linear decay: 20pts at day 0, 2pts at day 30
        score = 20.0 - ((age_days / 30.0) * 18.0)
        return round(max(score, 2.0), 2)

    except (ValueError, TypeError):
        return 5.0


# ─── MAIN SCORING FUNCTION ────────────────────────────────────────────────────

def calculate_threat_score(
    source: str,
    severity: str,
    category: str,
    last_seen: str = "",
    known_ransomware: bool = False,
) -> float:
    """
    Calculate the Kulan Threat Score for an IOC.

    Parameters
    ----------
    source          : Feed source name (e.g. 'CISA_KEV', 'OTX')
    severity        : Severity string ('critical', 'high', 'medium', 'low')
    category        : Threat category string (e.g. 'ransomware', 'phishing')
    last_seen       : ISO 8601 timestamp of last observation
    known_ransomware: True if CISA KEV flags as ransomware campaign

    Returns
    -------
    float : Threat score 0.0–100.0
    """

    # 1. Source reliability (0–25)
    src_score = SOURCE_WEIGHTS.get(source.upper() if source else "", 10)

    # 2. Severity (0–30)
    sev_score = SEVERITY_SCORES.get(severity.lower() if severity else "unknown", 3)

    # 3. Recency (0–20)
    rec_score = recency_score(last_seen)

    # 4. Category weight (0–15)
    cat_score = CATEGORY_WEIGHTS.get(category.lower() if category else "unknown", 3)

    # 5. Ransomware campaign bonus (0–10)
    ransomware_bonus = 10 if known_ransomware else 0

    total = src_score + sev_score + rec_score + cat_score + ransomware_bonus

    # Cap at 100
    return round(min(total, 100.0), 2)


# ─── SEVERITY INFERENCE ──────────────────────────────────────────────────────

def infer_severity_from_score(score: float) -> str:
    """
    Convert a numeric threat score back to a severity label.
    Used when a feed doesn't provide explicit severity.
    """
    if score >= 75:
        return "critical"
    elif score >= 55:
        return "high"
    elif score >= 35:
        return "medium"
    else:
        return "low"


def severity_from_cvss(cvss: float) -> str:
    """Map CVSS v3 base score to severity label per NVD standard."""
    if cvss >= 9.0:
        return "critical"
    elif cvss >= 7.0:
        return "high"
    elif cvss >= 4.0:
        return "medium"
    elif cvss > 0:
        return "low"
    return "unknown"


# ─── ENVIRONMENT RISK SCORE ───────────────────────────────────────────────────

def calculate_environment_risk(ioc_counts: dict, alert_count: int) -> int:
    """
    Aggregate risk score for the overall monitored environment (0–100).

    ioc_counts: dict with keys 'critical', 'high', 'medium', 'low'
    alert_count: number of open alerts

    Used to power the dashboard's "Environment Risk Score" gauge.
    """
    risk = 0

    # IOC severity weighting
    risk += ioc_counts.get("critical", 0) * 4.0
    risk += ioc_counts.get("high", 0) * 2.0
    risk += ioc_counts.get("medium", 0) * 0.8
    risk += ioc_counts.get("low", 0) * 0.2

    # Alert penalty
    risk += alert_count * 1.5

    # Normalize to 0–100
    # Calibration: 25 critical IOCs + 10 alerts should be ~100 (max risk)
    baseline_max = (25 * 4.0) + (10 * 1.5)
    normalized = (risk / baseline_max) * 100

    return int(min(normalized, 100))


# ─── SELF-TEST ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("KULAN THREAT SCORE ENGINE — Self-Test")
    print("=" * 55)

    test_cases = [
        {
            "label": "CISA KEV / Critical / Ransomware / Fresh",
            "source": "CISA_KEV", "severity": "critical",
            "category": "ransomware", "last_seen": datetime.utcnow().isoformat(),
            "known_ransomware": True,
        },
        {
            "label": "OTX / High / Phishing / 5 days old",
            "source": "OTX", "severity": "high",
            "category": "phishing",
            "last_seen": "2026-03-25T10:00:00",
            "known_ransomware": False,
        },
        {
            "label": "AbuseIPDB / Medium / Scanner / 20 days old",
            "source": "AbuseIPDB", "severity": "medium",
            "category": "scanner",
            "last_seen": "2026-03-10T10:00:00",
            "known_ransomware": False,
        },
        {
            "label": "OSINT / Low / Brute-force / Stale (35 days)",
            "source": "OSINT", "severity": "low",
            "category": "brute-force",
            "last_seen": "2026-02-23T10:00:00",
            "known_ransomware": False,
        },
    ]

    for tc in test_cases:
        score = calculate_threat_score(
            source=tc["source"],
            severity=tc["severity"],
            category=tc["category"],
            last_seen=tc["last_seen"],
            known_ransomware=tc["known_ransomware"],
        )
        print(f"\n  {tc['label']}")
        print(f"  → Threat Score: {score:5.1f} / 100  "
              f"[{infer_severity_from_score(score).upper()}]")

    # Environment risk
    print("\n" + "-" * 55)
    counts = {"critical": 12, "high": 25, "medium": 40, "low": 60}
    env_risk = calculate_environment_risk(counts, alert_count=8)
    print(f"\n  Environment Risk Score: {env_risk} / 100")
    print("=" * 55)
