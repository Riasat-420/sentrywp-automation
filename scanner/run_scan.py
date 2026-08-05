"""
SentryWP — Main Scan Orchestrator
===================================
This is the entry point called by GitHub Actions.
It reads clients.json, loads FTP credentials from SITES_CONFIG env var,
and runs the full scan pipeline for every active client site.
"""

import os
import sys
import json
import time
import shutil
import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.ftp_handler import FTPHandler
from scanner.ai_analysis import analyse_with_gemini
from scanner.autofix import run_autofix
from scanner.notify import send_telegram_alert, send_email_report
from scanner.logger import log_to_sheet
from scanner.report import generate_pdf_report

# ─── Configuration ────────────────────────────────────────────────────────────

CLIENTS_FILE   = Path(__file__).parent.parent / "clients.json"
TOOLS_DIR      = Path(__file__).parent.parent / "tools"
RESULTS_DIR    = Path(__file__).parent.parent / "scan_results"
REPORTS_DIR    = Path(__file__).parent.parent / "reports"
SCANNER_PHP    = TOOLS_DIR / "deep_scanner_v2.php"
HARDEN_SCRIPT  = TOOLS_DIR / "harden_generic.py"
SHIELD_PHP     = TOOLS_DIR / "security-firewall-shield.php"

SCAN_MODE        = os.environ.get("SCAN_MODE", "quick")          # quick | deep
GENERATE_REPORTS = os.environ.get("GENERATE_REPORTS", "false") == "true"
FILTER_SITE_ID   = os.environ.get("SCAN_SITE_ID", "").strip()

# ─── Load client registry ─────────────────────────────────────────────────────

def load_clients():
    with open(CLIENTS_FILE, "r") as f:
        clients = json.load(f)
    return [c for c in clients if c.get("active", True)]


def load_ftp_credentials():
    """
    FTP credentials are stored as a JSON blob in the SITES_CONFIG GitHub Secret.
    Format:
    {
      "kashmir_gems": { "ftp_host": "...", "ftp_user": "...", "ftp_pass": "..." },
      "camali_bijoux": { "ftp_host": "...", "ftp_user": "...", "ftp_pass": "..." }
    }
    """
    raw = os.environ.get("SITES_CONFIG", "{}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        print("[-] ERROR: SITES_CONFIG secret is not valid JSON. Check GitHub Secrets.")
        sys.exit(1)


# ─── Per-site scan pipeline ───────────────────────────────────────────────────

def scan_site(client: dict, creds: dict) -> dict:
    site_id   = client["id"]
    site_name = client["name"]
    site_url  = client["url"].rstrip("/")
    wp_root   = client.get("wp_root", "/")

    ftp_host = creds.get("ftp_host", "")
    ftp_user = creds.get("ftp_user", "")
    ftp_pass = creds.get("ftp_pass", "")

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    print(f"\n{'='*60}")
    print(f"  🔍 Scanning: {site_name} ({site_url})")
    print(f"  FTP: {ftp_user}@{ftp_host}")
    print(f"{'='*60}")

    result = {
        "site_id":   site_id,
        "site_name": site_name,
        "url":       site_url,
        "timestamp": timestamp,
        "scan_mode": SCAN_MODE,
        "ftp_ok":    False,
        "scan_data": None,
        "ai":        None,
        "actions":   [],
        "error":     None,
    }

    # ── Step 1: FTP Connection ────────────────────────────────────────────────
    ftp = FTPHandler(ftp_host, ftp_user, ftp_pass)
    if not ftp.connect():
        result["error"] = "FTP connection failed"
        print(f"  ❌ FTP failed for {site_name}")
        return result

    result["ftp_ok"] = True
    print(f"  ✅ FTP connected")

    # ── Step 2: Upload & Run Scanner (Security Layer 5) ───────────────────────
    scanner_remote = f"{wp_root.rstrip('/')}/sentrywp_scan_{timestamp}.php"
    scanner_url    = f"{site_url}/sentrywp_scan_{timestamp}.php"

    print(f"  📤 Uploading scanner...")
    upload_ok = ftp.upload_file(str(SCANNER_PHP), scanner_remote)
    if not upload_ok:
        result["error"] = "Scanner upload failed"
        ftp.close()
        return result

    # Give server a moment to register the file
    time.sleep(2)

    print(f"  🌐 Running scanner via HTTP...")
    scan_data = ftp.http_get_json(scanner_url)

    # Scanner self-deletes, but try via FTP too as backup
    try:
        ftp.delete_file(scanner_remote)
    except Exception:
        pass  # Already self-deleted

    if scan_data is None:
        result["error"] = "Scanner returned no data (HTTP failed)"
        ftp.close()
        return result

    result["scan_data"] = scan_data

    total_files    = scan_data.get("total_files_scanned", 0)
    core_mods      = scan_data.get("core_modifications", [])
    suspicious     = scan_data.get("suspicious_anomalies", [])
    bad_uploads    = scan_data.get("suspicious_uploads", [])
    total_flags    = len(core_mods) + len(suspicious) + len(bad_uploads)

    print(f"  📊 Files scanned: {total_files}")
    print(f"  🚩 Flags found:   {total_flags} (core:{len(core_mods)} anomalies:{len(suspicious)} uploads:{len(bad_uploads)})")

    # ── Step 3: AI Analysis ───────────────────────────────────────────────────
    if total_flags > 0:
        print(f"  🤖 Sending findings to Gemini AI...")
        ai_result = analyse_with_gemini(site_name, scan_data)
        result["ai"] = ai_result
        severity = ai_result.get("severity", "low").lower()
        print(f"  🎯 AI Severity: {severity.upper()} (confidence: {ai_result.get('confidence', 0):.0%})")
    else:
        result["ai"] = {"severity": "clean", "confidence": 1.0, "summary": "No threats detected."}
        severity = "clean"
        print(f"  ✅ AI: CLEAN — no threats detected")

    # ── Step 4: Auto-Fix (if needed) ─────────────────────────────────────────
    if severity in ("critical", "high"):
        print(f"  🔧 Severity={severity.upper()} — firing auto-fix pipeline...")
        actions = run_autofix(
            ftp=ftp,
            client=client,
            scan_data=scan_data,
            severity=severity,
            tools_dir=TOOLS_DIR,
            timestamp=timestamp,
        )
        result["actions"] = actions
    elif severity == "medium":
        print(f"  ⚠️  Severity=MEDIUM — alerting only, no auto-fix (requires manual review)")
        result["actions"] = ["alert_only"]

    ftp.close()

    # ── Step 5: Save raw result JSON ─────────────────────────────────────────
    RESULTS_DIR.mkdir(exist_ok=True)
    result_file = RESULTS_DIR / f"{site_id}_{timestamp}.json"
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2, default=str)

    return result


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("\n🛡️  SentryWP Automation — Starting Scan Pipeline")
    print(f"   Mode: {SCAN_MODE.upper()} | Time: {datetime.datetime.utcnow().isoformat()}Z\n")

    clients    = load_clients()
    all_creds  = load_ftp_credentials()

    # Filter to single site if manually triggered with site_id
    if FILTER_SITE_ID:
        clients = [c for c in clients if c["id"] == FILTER_SITE_ID]
        if not clients:
            print(f"[-] No active client found with id '{FILTER_SITE_ID}'")
            sys.exit(1)

    print(f"  📋 Sites to scan: {len(clients)}")
    for c in clients:
        print(f"      • {c['name']} ({c['id']})")

    all_results  = []
    critical_sites = []

    for client in clients:
        site_id = client["id"]
        creds   = all_creds.get(site_id)

        if not creds:
            print(f"\n  ⚠️  No FTP credentials found for '{site_id}' in SITES_CONFIG secret — skipping.")
            continue

        result = scan_site(client, creds)
        all_results.append(result)

        severity = (result.get("ai") or {}).get("severity", "unknown")
        if severity in ("critical", "high"):
            critical_sites.append(result)

    # ── Post-scan: Notifications ──────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  📬 Sending notifications...")
    print(f"{'='*60}")

    for result in all_results:
        severity = (result.get("ai") or {}).get("severity", "unknown")

        if severity == "clean":
            # Silent — just log
            pass
        else:
            send_telegram_alert(result)

        # Log every result to Google Sheets
        log_to_sheet(result)

    # ── Post-scan: PDF Reports (weekly mode or critical) ──────────────────────
    if GENERATE_REPORTS or critical_sites:
        print(f"\n  📄 Generating PDF reports...")
        REPORTS_DIR.mkdir(exist_ok=True)
        for result in all_results:
            if GENERATE_REPORTS or result in critical_sites:
                client = next((c for c in clients if c["id"] == result["site_id"]), None)
                if client:
                    pdf_path = generate_pdf_report(result, client, REPORTS_DIR)
                    if pdf_path and client.get("notify_email"):
                        send_email_report(pdf_path, client, result)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  🏁 Scan Complete — {len(all_results)} sites processed")
    clean    = sum(1 for r in all_results if (r.get("ai") or {}).get("severity") == "clean")
    threats  = len(all_results) - clean
    print(f"  ✅ Clean:    {clean}")
    print(f"  🚨 Threats:  {threats}")
    print(f"{'='*60}\n")

    # Exit with error code if any critical threats found (makes GitHub Actions mark run as failed = red badge)
    if critical_sites:
        sys.exit(1)


if __name__ == "__main__":
    main()
