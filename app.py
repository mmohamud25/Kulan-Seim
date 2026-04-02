"""
app.py — Kulan Threat Intelligence Platform
Flask REST API: serves the dashboard with live data from SQLite.

Endpoints:
    GET  /                        → Dashboard HTML
    GET  /api/iocs                → IOC feed (filterable)
    GET  /api/kev                 → CISA KEV entries
    GET  /api/alerts              → Active alert queue
    GET  /api/metrics             → KPI counts for dashboard
    GET  /api/ingest/run          → Trigger a feed sync manually
    GET  /api/health              → Health check

Run:
    python app.py

Author: Mohamed Mohamud
"""

import json
import os
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

import db
import score
import ingest

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)  # Allow GitHub Pages frontend to call this API

# ─── HEALTH ──────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "platform": "Kulan Threat Intelligence Platform",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "author": "Mohamed Mohamud",
    })


# ─── IOC ENDPOINTS ───────────────────────────────────────────────────────────

@app.route("/api/iocs")
def get_iocs():
    """
    Return IOC list with optional filters.

    Query params:
        severity  : critical | high | medium | low
        category  : malware | phishing | ransomware | c2 | exploit | scanner
        status    : active | watching | resolved
        limit     : int (default 100)
    """
    severity = request.args.get("severity")
    category = request.args.get("category")
    status   = request.args.get("status")
    limit    = int(request.args.get("limit", 100))

    iocs = db.get_iocs(
        severity=severity,
        category=category,
        status=status,
        limit=limit,
    )

    return jsonify({
        "count": len(iocs),
        "filters": {"severity": severity, "category": category, "status": status},
        "data": iocs,
    })


@app.route("/api/iocs/stats")
def ioc_stats():
    """Category and severity breakdown for charts."""
    all_iocs = db.get_iocs(limit=1000)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_counts = {}
    source_counts   = {}

    for ioc in all_iocs:
        sev = ioc.get("severity", "unknown")
        cat = ioc.get("category", "unknown")
        src = ioc.get("source", "unknown")

        if sev in severity_counts:
            severity_counts[sev] += 1

        category_counts[cat] = category_counts.get(cat, 0) + 1
        source_counts[src]   = source_counts.get(src, 0) + 1

    return jsonify({
        "by_severity": severity_counts,
        "by_category": sorted(category_counts.items(), key=lambda x: -x[1]),
        "by_source":   sorted(source_counts.items(), key=lambda x: -x[1]),
    })


# ─── CISA KEV ENDPOINTS ──────────────────────────────────────────────────────

@app.route("/api/kev")
def get_kev():
    """Return CISA KEV entries, newest first."""
    limit = int(request.args.get("limit", 20))
    ransomware_only = request.args.get("ransomware") == "true"
    entries = db.get_kev_entries(limit=limit, ransomware_only=ransomware_only)
    return jsonify({
        "count": len(entries),
        "total_in_db": db.get_kev_count(),
        "data": entries,
    })


# ─── ALERT ENDPOINTS ─────────────────────────────────────────────────────────

@app.route("/api/alerts")
def get_alerts():
    """Return alert queue."""
    status = request.args.get("status", "open")
    limit  = int(request.args.get("limit", 20))
    alerts = db.get_alerts(status=status, limit=limit)
    return jsonify({
        "count": len(alerts),
        "status_filter": status,
        "data": alerts,
    })


# ─── METRICS ENDPOINT ────────────────────────────────────────────────────────

@app.route("/api/metrics")
def get_metrics():
    """
    Aggregated KPIs for the dashboard.
    This is the primary endpoint the dashboard polls.
    """
    ioc_counts  = db.get_ioc_counts()
    alert_count = db.get_alert_count("open")
    kev_count   = db.get_kev_count()
    env_risk    = score.calculate_environment_risk(ioc_counts, alert_count)

    # Count blocked IPs (resolved IOCs of type IP)
    blocked = db.get_iocs(status="resolved", limit=1000)
    blocked_ips = sum(1 for i in blocked if i.get("ioc_type") == "ip")

    return jsonify({
        "critical_iocs":  ioc_counts.get("critical", 0),
        "high_iocs":      ioc_counts.get("high", 0),
        "medium_iocs":    ioc_counts.get("medium", 0),
        "low_iocs":       ioc_counts.get("low", 0),
        "active_alerts":  alert_count,
        "ips_blocked":    blocked_ips,
        "kev_count":      kev_count,
        "environment_risk_score": env_risk,
        "mttd_minutes":   14,          # Placeholder — wire to real data in v3
        "timestamp":      datetime.utcnow().isoformat() + "Z",
    })


# ─── INGEST TRIGGER ──────────────────────────────────────────────────────────

@app.route("/api/ingest/run")
def trigger_ingest():
    """
    Manually trigger a feed sync.
    In production this would be a POST + background job (Celery/cron).
    For portfolio: a GET is fine for demo purposes.

    Query params:
        feed: kev | otx | all (default: all)
    """
    feed = request.args.get("feed", "all")

    if feed == "kev":
        result = ingest.ingest_cisa_kev()
    elif feed == "otx":
        result = ingest.ingest_otx()
    else:
        result = ingest.run_all_feeds()

    return jsonify({
        "status": "completed",
        "feed": feed,
        "result": result,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# ─── DASHBOARD SERVE ─────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    """Serve the dashboard HTML file."""
    dashboard_path = os.path.join(
        os.path.dirname(__file__), "..", "kulan-threat-intel-dashboard.html"
    )
    if os.path.exists(dashboard_path):
        with open(dashboard_path, "r") as f:
            return f.read()
    return """
    <html><body style="background:#060b14;color:#c8d8f0;font-family:monospace;padding:40px;">
    <h2>Kulan TIP API — Running</h2>
    <p>Dashboard file not found. API endpoints are active:</p>
    <ul>
      <li><a href="/api/health" style="color:#00c8ff;">/api/health</a></li>
      <li><a href="/api/metrics" style="color:#00c8ff;">/api/metrics</a></li>
      <li><a href="/api/iocs" style="color:#00c8ff;">/api/iocs</a></li>
      <li><a href="/api/kev" style="color:#00c8ff;">/api/kev</a></li>
      <li><a href="/api/alerts" style="color:#00c8ff;">/api/alerts</a></li>
      <li><a href="/api/ingest/run" style="color:#00c8ff;">/api/ingest/run</a></li>
    </ul>
    </body></html>
    """


# ─── ERROR HANDLERS ──────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found", "status": 404}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error", "status": 500}), 500


# ─── STARTUP ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  KULAN THREAT INTELLIGENCE PLATFORM v2.0")
    print("  Author: Mohamed Mohamud | Columbus, OH")
    print("=" * 55)

    # Ensure DB exists
    db.init_db()

    # Run an initial ingest on startup if DB is empty
    kev_count = db.get_kev_count()
    if kev_count == 0:
        print("\n[startup] Empty database detected. Running initial feed sync...")
        ingest.run_all_feeds()
    else:
        print(f"\n[startup] Database ready. {kev_count} KEV entries loaded.")

    port = int(os.environ.get("PORT", 5000))
    print(f"\n[startup] Starting Flask API on port {port}")
    print("[startup] Press CTRL+C to stop.\n")
    app.run(debug=False, host="0.0.0.0", port=port)
