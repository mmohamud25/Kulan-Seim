"""
ingest.py — Kulan Threat Intelligence Platform
Feed Ingestion Engine: pulls live data from public threat intel sources.

Supported Feeds:
    1. CISA Known Exploited Vulnerabilities (KEV)  — no API key required
    2. AlienVault OTX (pulse subscriptions)        — free API key required
    3. AbuseIPDB                                   — free API key required (stub)

Run:
    python ingest.py              # run all feeds
    python ingest.py --feed kev   # run only CISA KEV
    python ingest.py --feed otx   # run only OTX
    python ingest.py --dry-run    # fetch but do not write to DB

Author: Mohamed Mohamud
"""

import json
import argparse
import requests
from datetime import datetime

import db
import score

# ─── CONFIG ──────────────────────────────────────────────────────────────────
# Replace with your real keys in a .env file for production.
# For portfolio/demo use, CISA KEV requires no key.
OTX_API_KEY = "YOUR_OTX_API_KEY_HERE"      # free at otx.alienvault.com
ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_KEY_HERE"  # free at abuseipdb.com

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OTX_PULSE_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

REQUEST_TIMEOUT = 15  # seconds


# ─── FEED 1: CISA KNOWN EXPLOITED VULNERABILITIES ────────────────────────────

def ingest_cisa_kev(dry_run=False):
    """
    Pull the full CISA KEV catalog (JSON) and store each CVE entry.
    CISA publishes this list publicly — no authentication required.

    CISA KEV = vulnerabilities that are confirmed to be actively exploited
    in the wild. Patching these is required for federal agencies within set
    deadlines. For any SOC, these are the highest-priority vulnerabilities.
    """
    print("\n[CISA KEV] Starting ingestion...")
    added = skipped = errors = 0

    try:
        resp = requests.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        print(f"[CISA KEV] Fetched {len(vulnerabilities)} entries from catalog.")

        for vuln in vulnerabilities:
            try:
                # Determine if this is flagged for ransomware campaigns
                is_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known"

                # Calculate our threat score for this CVE
                threat_score = score.calculate_threat_score(
                    source="CISA_KEV",
                    severity="critical",          # All KEV entries are critical by definition
                    category="ransomware" if is_ransomware else "exploit",
                    last_seen=vuln.get("dateAdded", ""),
                    known_ransomware=is_ransomware,
                )

                vuln["threat_score"] = threat_score

                if not dry_run:
                    result = db.upsert_kev(vuln)
                    if "error" in str(result):
                        errors += 1
                    else:
                        # Also write to IOC table so it appears in the main feed
                        ioc_result = db.upsert_ioc(
                            indicator=vuln.get("cveID", ""),
                            ioc_type="cve",
                            severity="critical",
                            category="ransomware" if is_ransomware else "exploit",
                            source="CISA_KEV",
                            description=vuln.get("shortDescription", "")[:300],
                            threat_score=threat_score,
                            raw_json=json.dumps(vuln),
                        )
                        if ioc_result == "inserted":
                            added += 1
                        elif ioc_result == "updated":
                            skipped += 1
                        else:
                            errors += 1
                else:
                    # Dry run: just print first 5
                    if added < 5:
                        print(f"  [DRY] {vuln.get('cveID')} — Score: {threat_score} "
                              f"— Ransomware: {is_ransomware}")
                    added += 1

                # Auto-generate alert for ransomware-linked KEV entries
                if is_ransomware and not dry_run:
                    db.create_alert(
                        title=f"CISA KEV: {vuln.get('cveID')} linked to ransomware campaign",
                        detail=(f"{vuln.get('vendorProject', '')} {vuln.get('product', '')} — "
                                f"{vuln.get('vulnerabilityName', '')}. "
                                f"Due: {vuln.get('dueDate', 'N/A')}"),
                        severity="critical",
                        category="ransomware",
                        ioc_ref=vuln.get("cveID", ""),
                        source="CISA_KEV",
                    )

            except Exception as e:
                errors += 1
                print(f"  [CISA KEV] Error processing {vuln.get('cveID', '?')}: {e}")

        status = "success" if errors == 0 else "partial"
        if not dry_run:
            db.log_ingest("CISA_KEV", status, added, skipped,
                          f"{errors} errors" if errors else "")

        print(f"[CISA KEV] Done — Added: {added} | Skipped/Updated: {skipped} | Errors: {errors}")
        return {"added": added, "skipped": skipped, "errors": errors}

    except requests.exceptions.ConnectionError:
        msg = "Network unavailable — running in offline/demo mode."
        print(f"[CISA KEV] {msg}")
        if not dry_run:
            db.log_ingest("CISA_KEV", "error", 0, 0, msg)
        return {"added": 0, "skipped": 0, "errors": 1, "note": msg}

    except requests.exceptions.RequestException as e:
        msg = str(e)
        print(f"[CISA KEV] Request error: {msg}")
        if not dry_run:
            db.log_ingest("CISA_KEV", "error", 0, 0, msg)
        return {"added": 0, "skipped": 0, "errors": 1}


# ─── FEED 2: ALIENVAULT OTX ──────────────────────────────────────────────────

def ingest_otx(dry_run=False):
    """
    Pull subscribed pulses from AlienVault OTX and extract IOC indicators.

    Each OTX pulse contains a threat report + list of indicators (IOCs).
    Indicator types we care about: IPv4, domain, hostname, URL, FileHash-MD5.

    To use: sign up at otx.alienvault.com (free), get your API key,
    and replace OTX_API_KEY above or set env var OTX_API_KEY.
    """
    print("\n[OTX] Starting ingestion...")

    if OTX_API_KEY == "YOUR_OTX_API_KEY_HERE":
        print("[OTX] No API key configured — loading demo data instead.")
        return _ingest_otx_demo(dry_run)

    added = skipped = errors = 0

    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        params = {"limit": 50, "page": 1}
        resp = requests.get(OTX_PULSE_URL, headers=headers,
                            params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        pulses = data.get("results", [])
        print(f"[OTX] Fetched {len(pulses)} pulses.")

        for pulse in pulses:
            pulse_name = pulse.get("name", "Unknown Pulse")
            tags = pulse.get("tags", [])

            # Infer category from pulse tags
            category = _infer_category_from_tags(tags)

            for indicator in pulse.get("indicators", []):
                ioc_type_raw = indicator.get("type", "").lower()
                ioc_value = indicator.get("indicator", "")

                # Normalize OTX type names to our schema
                type_map = {
                    "ipv4": "ip", "ipv6": "ip",
                    "domain": "domain", "hostname": "domain",
                    "url": "url",
                    "filehash-md5": "hash", "filehash-sha256": "hash",
                    "filehash-sha1": "hash",
                }
                ioc_type = type_map.get(ioc_type_raw, "unknown")
                if ioc_type == "unknown":
                    continue

                threat_score = score.calculate_threat_score(
                    source="OTX",
                    severity="high",      # OTX doesn't always include severity; default high
                    category=category,
                    last_seen=datetime.utcnow().isoformat(),
                )
                severity = score.infer_severity_from_score(threat_score)

                if not dry_run:
                    result = db.upsert_ioc(
                        indicator=ioc_value,
                        ioc_type=ioc_type,
                        severity=severity,
                        category=category,
                        source="OTX",
                        description=f"Pulse: {pulse_name}",
                        threat_score=threat_score,
                        raw_json=json.dumps({"pulse": pulse_name, "tags": tags}),
                    )
                    if result == "inserted":
                        added += 1
                    elif result == "updated":
                        skipped += 1
                    else:
                        errors += 1
                else:
                    added += 1

        if not dry_run:
            db.log_ingest("OTX", "success", added, skipped)

        print(f"[OTX] Done — Added: {added} | Updated: {skipped} | Errors: {errors}")
        return {"added": added, "skipped": skipped, "errors": errors}

    except requests.exceptions.RequestException as e:
        msg = str(e)
        print(f"[OTX] Request error: {msg}")
        if not dry_run:
            db.log_ingest("OTX", "error", 0, 0, msg)
        return {"added": 0, "skipped": 0, "errors": 1}


def _ingest_otx_demo(dry_run=False):
    """
    Load realistic OTX-format demo data when no API key is configured.
    This keeps the dashboard functional for portfolio demos.
    """
    print("[OTX] Loading demo IOC dataset (12 indicators)...")

    demo_iocs = [
        # (indicator, type, severity, category, description)
        ("185.220.101.47",   "ip",     "critical", "c2",         "TOR exit node / Cobalt Strike C2 beacon"),
        ("103.76.228.48",    "ip",     "high",     "ransomware",  "LockBit 3.0 infrastructure IP"),
        ("91.92.248.101",    "ip",     "high",     "malware",     "Emotet loader distribution node"),
        ("5.188.86.172",     "ip",     "medium",   "brute-force", "SSH brute-force origin, 1200+ attempts"),
        ("194.165.16.77",    "ip",     "low",      "scanner",     "Shodan-indexed port scanner"),
        ("emotet-drop.net",  "domain", "critical", "malware",     "Emotet stage-2 payload drop domain"),
        ("update-chrome.ru", "domain", "high",     "phishing",    "Fake Chrome update phishing page"),
        ("d3ad.xyz",         "domain", "medium",   "c2",          "Cobalt Strike beacon C2 domain"),
        ("payroll-update.com","domain","high",     "phishing",    "BEC phishing — impersonating payroll"),
        ("44a3b1c9d2e5f6b7a8c9d0e1f2a3b4c5", "hash", "critical", "malware", "Emotet dropper SHA256"),
        ("badfile.exe.ru",   "domain", "high",     "malware",     "Malware delivery infrastructure"),
        ("192.168.phish.io", "domain", "medium",   "phishing",    "Lookalike domain targeting finance"),
    ]

    added = 0
    for ind, typ, sev, cat, desc in demo_iocs:
        ts = score.calculate_threat_score(
            source="OTX", severity=sev, category=cat,
            last_seen=datetime.utcnow().isoformat(),
        )
        if not dry_run:
            result = db.upsert_ioc(
                indicator=ind, ioc_type=typ, severity=sev,
                category=cat, source="OTX", description=desc,
                threat_score=ts,
            )
            if result in ("inserted", "updated"):
                added += 1
        else:
            added += 1
            print(f"  [DRY] {ind} ({typ}) — Score: {ts}")

    if not dry_run:
        db.log_ingest("OTX_DEMO", "success", added, 0)
    print(f"[OTX] Demo data loaded — {added} indicators.")
    return {"added": added, "skipped": 0, "errors": 0}


# ─── FEED 3: ABUSEIPDB (STUB) ────────────────────────────────────────────────

def ingest_abuseipdb(dry_run=False):
    """
    Pull blocklist from AbuseIPDB (top abusive IPs, last 24h).
    Requires free API key from abuseipdb.com.
    This is a stub — wired up but key-gated for portfolio safety.
    """
    print("\n[AbuseIPDB] Starting ingestion...")

    if ABUSEIPDB_KEY == "YOUR_ABUSEIPDB_KEY_HERE":
        print("[AbuseIPDB] No API key configured — skipping.")
        return {"added": 0, "skipped": 0, "errors": 0, "note": "No API key"}

    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"confidenceMinimum": 90, "limit": 100}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        added = skipped = errors = 0
        for entry in data.get("data", []):
            ip = entry.get("ipAddress", "")
            confidence = entry.get("abuseConfidenceScore", 0)
            severity = "critical" if confidence >= 95 else "high" if confidence >= 80 else "medium"
            ts = score.calculate_threat_score(
                source="AbuseIPDB", severity=severity, category="scanner",
                last_seen=datetime.utcnow().isoformat(),
            )
            if not dry_run:
                result = db.upsert_ioc(
                    indicator=ip, ioc_type="ip", severity=severity,
                    category="scanner", source="AbuseIPDB",
                    description=f"AbuseIPDB confidence: {confidence}%",
                    threat_score=ts,
                )
                if result == "inserted": added += 1
                elif result == "updated": skipped += 1
                else: errors += 1
            else:
                added += 1

        db.log_ingest("AbuseIPDB", "success", added, skipped)
        print(f"[AbuseIPDB] Done — Added: {added} | Updated: {skipped}")
        return {"added": added, "skipped": skipped, "errors": errors}

    except requests.exceptions.RequestException as e:
        print(f"[AbuseIPDB] Error: {e}")
        db.log_ingest("AbuseIPDB", "error", 0, 0, str(e))
        return {"added": 0, "skipped": 0, "errors": 1}


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _infer_category_from_tags(tags: list) -> str:
    """
    Infer threat category from OTX pulse tags.
    Simple keyword matching — expandable with ML later.
    """
    tag_str = " ".join(tags).lower()
    if any(k in tag_str for k in ["ransomware", "lockbit", "blackcat", "clop"]):
        return "ransomware"
    if any(k in tag_str for k in ["phishing", "bec", "credential"]):
        return "phishing"
    if any(k in tag_str for k in ["c2", "c&c", "cobalt", "beacon", "command"]):
        return "c2"
    if any(k in tag_str for k in ["malware", "trojan", "loader", "rat", "emotet"]):
        return "malware"
    if any(k in tag_str for k in ["exploit", "rce", "cve", "vulnerability"]):
        return "exploit"
    if any(k in tag_str for k in ["bruteforce", "brute", "ssh", "rdp"]):
        return "brute-force"
    return "malware"  # default


# ─── CLI ENTRY POINT ─────────────────────────────────────────────────────────

def run_all_feeds(dry_run=False):
    """Run all configured feeds in sequence."""
    print("\n" + "=" * 55)
    print("KULAN TIP — Feed Ingestion Run")
    print(f"Time: {datetime.utcnow().isoformat()} UTC")
    print(f"Mode: {'DRY RUN (no DB writes)' if dry_run else 'LIVE'}")
    print("=" * 55)

    results = {}
    results["cisa_kev"] = ingest_cisa_kev(dry_run=dry_run)
    results["otx"] = ingest_otx(dry_run=dry_run)
    results["abuseipdb"] = ingest_abuseipdb(dry_run=dry_run)

    total_added = sum(r.get("added", 0) for r in results.values())
    total_errors = sum(r.get("errors", 0) for r in results.values())

    print("\n" + "=" * 55)
    print(f"INGEST COMPLETE — Total added: {total_added} | Errors: {total_errors}")
    print("=" * 55 + "\n")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kulan TIP — Feed Ingestor")
    parser.add_argument("--feed", choices=["kev", "otx", "abuseipdb", "all"],
                        default="all", help="Which feed to run")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch data but do not write to database")
    args = parser.parse_args()

    # Always ensure DB is initialized
    db.init_db()

    if args.feed == "kev":
        ingest_cisa_kev(dry_run=args.dry_run)
    elif args.feed == "otx":
        ingest_otx(dry_run=args.dry_run)
    elif args.feed == "abuseipdb":
        ingest_abuseipdb(dry_run=args.dry_run)
    else:
        run_all_feeds(dry_run=args.dry_run)
