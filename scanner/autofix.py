"""
SentryWP — Auto-Fix Pipeline
==============================
Fires the appropriate security layers based on AI severity assessment.
Uses HTTP Bridge for execution (no FTP required).

Security Layers:
  Layer 1 & 2 — Root & Uploads .htaccess firewalls (bridge.harden())
  Layer 3     — Permanent PHP firewall shield       (bridge.deploy_shield())
  Layer 5     — File system scan & cleanup          (bridge.cleanup())
"""

import os
import json
from pathlib import Path


def run_autofix(bridge, client: dict, scan_data: dict, severity: str,
                tools_dir: Path, timestamp: str) -> list[str]:
    """
    Fire the appropriate security layers based on severity using BridgeHandler.
    """
    site_url = client["url"].rstrip("/")
    actions  = []

    print(f"\n  🔧 Auto-Fix Pipeline — Severity: {severity.upper()}")
    print(f"  Site: {client['name']} ({site_url}) via HTTP Bridge")

    # Layers 1 & 2 — .htaccess Hardening
    harden_res = bridge.harden()
    if harden_res and harden_res.get("status") == "complete":
        for log_entry in harden_res.get("log", []):
            actions.append(log_entry)
            print(f"  ✅ {log_entry}")
    else:
        actions.append("Layers 1 & 2 (FAILED): Could not write .htaccess via bridge")
        print("  ❌ Layers 1 & 2 (FAILED)")

    # Layer 3 — Permanent PHP Firewall Shield (mu-plugins)
    shield_file = tools_dir / "security-firewall-shield.php"
    if shield_file.exists():
        with open(shield_file, "r", encoding="utf-8") as f:
            shield_content = f.read()

        shield_res = bridge.deploy_shield(shield_content)
        if shield_res and shield_res.get("status") == "ok":
            msg = "Layer 3 (OK): PHP Firewall Shield deployed to mu-plugins"
            actions.append(msg)
            print(f"  ✅ {msg}")
        else:
            msg = "Layer 3 (FAILED): Could not deploy firewall shield"
            actions.append(msg)
            print(f"  ❌ {msg}")

    # Layer 5 — File Cleanup
    files_to_delete = []
    for finding in scan_data.get("suspicious_uploads", []):
        files_to_delete.append(finding["file"])

    if files_to_delete:
        cleanup_res = bridge.cleanup(files_to_delete)
        if cleanup_res and cleanup_res.get("status") == "complete":
            deleted = cleanup_res.get("deleted", 0)
            msg = f"Layer 5 (OK): Deleted {deleted}/{len(files_to_delete)} malicious files"
            actions.append(msg)
            print(f"  🧹 {msg}")
        else:
            msg = "Layer 5 (FAILED): Could not execute file cleanup via bridge"
            actions.append(msg)
            print(f"  ❌ {msg}")
    else:
        msg = "Layer 5 (SKIPPED): No confirmed malicious files to delete"
        actions.append(msg)
        print(f"  ℹ️ {msg}")

    print(f"\n  ✅ Auto-fix complete — {len(actions)} actions recorded")
    return actions
