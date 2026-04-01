# Kulan Threat Score Model — Methodology v1.0

**Author:** Mohamed Mohamud
**Project:** Kulan Threat Intelligence Platform
**Last Updated:** March 2026

---

## Purpose

Every threat intelligence platform needs a way to answer one question: *which IOC should I look at first?*

The Kulan Threat Score (KTS) is a 0–100 composite risk score assigned to each Indicator of Compromise (IOC) in the database. It drives prioritization across the SOC dashboard, alert queue, and environment risk gauge. Rather than relying on a single vendor's severity rating, KTS synthesizes five independent dimensions into a single actionable number.

---

## The Five Scoring Dimensions

```
KTS = Source Reliability (0–25)
    + Severity Mapping  (0–30)
    + Recency Decay     (0–20)
    + Category Weight   (0–15)
    + Ransomware Bonus  (0–10)
    ─────────────────────────
    Maximum             = 100
```

---

### 1. Source Reliability (0–25 points)

Not all threat feeds carry the same authority. A vulnerability confirmed by CISA as actively exploited in the wild is more actionable than a community-submitted IP reputation flag.

| Source | Points | Rationale |
|--------|--------|-----------|
| CISA KEV | 25 | Mandated reporting; confirmed active exploitation in US federal environments |
| AlienVault OTX | 20 | Peer-reviewed community pulses; large contributor base with moderation |
| AbuseIPDB | 17 | Crowd-sourced IP reputation; good signal-to-noise at high confidence thresholds |
| Manual (analyst-added) | 15 | Direct analyst judgment; authoritative but limited scale |
| OSINT | 12 | Open-source; variable quality and verification depth |

**Design decision:** CISA KEV receives the maximum source weight because its inclusion criteria are the strictest — a CVE must have confirmed in-the-wild exploitation evidence before CISA adds it to the catalog. This aligns with CISA's Binding Operational Directive 22-01, which requires federal agencies to remediate KEV entries on a mandated timeline.

---

### 2. Severity Mapping (0–30 points)

Severity labels from feeds are normalized to a four-tier scale. This dimension carries the highest maximum weight because severity most directly reflects potential impact.

| Severity | Points | Criteria |
|----------|--------|----------|
| Critical | 30 | RCE, auth bypass on internet-facing systems, CVSS ≥ 9.0, confirmed exploitation |
| High | 22 | Significant impact, active campaigns, CVSS 7.0–8.9 |
| Medium | 14 | Moderate impact, limited exploitation evidence, CVSS 4.0–6.9 |
| Low | 6 | Informational, recon activity, CVSS < 4.0 |

When a feed does not supply explicit severity (e.g., raw OTX pulses), severity is inferred from the calculated KTS using `infer_severity_from_score()`.

---

### 3. Recency Decay (0–20 points)

A threat indicator observed today is more operationally relevant than one last seen 25 days ago. The recency dimension applies a linear decay function.

```
Recency Score = 20 − ((age_in_days / 30) × 18)
```

| Age | Score |
|-----|-------|
| 0–1 days | ~20 pts |
| 5 days | ~17 pts |
| 15 days | ~11 pts |
| 25 days | ~5 pts |
| > 30 days | 2 pts (floor) |

**Design decision:** The floor at 2 points (rather than 0) reflects that stale IOCs still carry historical value — they may re-emerge in new campaigns. Completely zeroing them out would cause important infrastructure indicators to drop out of scoring unfairly.

---

### 4. Category Weight (0–15 points)

Threat categories carry different baseline risk profiles based on typical operational impact and response urgency.

| Category | Points | Rationale |
|----------|--------|-----------|
| Ransomware | 15 | Direct financial and operational disruption; recovery costs high |
| Exploit/RCE | 14 | System compromise; often precedes lateral movement |
| Malware | 13 | Payload delivery; payload type determines final severity |
| C2 | 12 | Active command channel indicates ongoing compromise |
| Phishing/BEC | 10 | Credential theft; entry point for most breaches |
| Brute Force | 7 | Credential attacks; lower urgency unless successful |
| Scanner/Recon | 4 | Pre-attack intelligence gathering; low immediate threat |

---

### 5. Ransomware Campaign Bonus (0 or 10 points)

CISA KEV entries that are explicitly linked to known ransomware campaigns receive a flat 10-point bonus. This reflects the heightened urgency of vulnerabilities actively weaponized in ransomware operations, which carry immediate financial and operational risk beyond the base CVE severity.

Source field: `knownRansomwareCampaignUse = "Known"` in the CISA KEV JSON catalog.

---

## Score Interpretation

| KTS Range | Label | Recommended Response |
|-----------|-------|----------------------|
| 85–100 | Critical | Immediate escalation; block/isolate; notify SOC lead |
| 65–84 | High | Triage within 4 hours; enrich with additional context |
| 40–64 | Medium | Review within 24 hours; watch for correlated activity |
| 20–39 | Low | Log and monitor; review in weekly threat review |
| 0–19 | Informational | Archive; no immediate action required |

---

## Environment Risk Score

Beyond individual IOC scoring, the platform calculates an **Environment Risk Score (0–100)** representing the aggregate threat posture of the monitored environment.

```
Raw Risk = (critical_iocs × 4.0)
         + (high_iocs × 2.0)
         + (medium_iocs × 0.8)
         + (low_iocs × 0.2)
         + (open_alerts × 1.5)

Normalized = (Raw Risk / Baseline Max) × 100
Baseline Max = (25 critical × 4.0) + (10 alerts × 1.5) = 115
```

**Calibration:** The baseline is set so that an environment with 25 unresolved critical IOCs and 10 open alerts scores 100 (maximum risk). This reflects a threshold beyond which the security team should declare an incident.

---

## Limitations and Future Improvements

The current model has several known limitations worth disclosing:

**No CVSS integration yet.** For CVEs, CVSS base scores are not yet factored into severity mapping beyond the feed's own label. A future version will pull CVSS v3.1 scores from the NVD API and use `severity_from_cvss()` to produce more precise severity assignments.

**Category inference is keyword-based.** For OTX pulses without explicit category labels, category is inferred from tag keywords. This is reliable for common threat families but may misclassify novel or obscure campaigns.

**No threat actor attribution.** The model does not currently weight IOCs by known threat actor sophistication or targeting patterns (e.g., APT41 vs. opportunistic criminals). MITRE ATT&CK technique tagging is planned for Phase 6.

**Recency is based on last_seen, not last_active.** Some IOCs (especially C2 domains) may cycle offline/online. A more robust implementation would track a per-IOC activity cadence.

---

## References

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA BOD 22-01 — Reducing the Significant Risk of Known Exploited Vulnerabilities](https://www.cisa.gov/binding-operational-directive-22-01)
- [AlienVault OTX API Documentation](https://otx.alienvault.com/api)
- [CVSS v3.1 Specification — FIRST](https://www.first.org/cvss/v3.1/specification-document)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST SP 800-150 — Guide to Cyber Threat Information Sharing](https://csrc.nist.gov/publications/detail/sp/800-150/final)
