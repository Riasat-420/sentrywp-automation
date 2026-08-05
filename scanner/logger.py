"""
SentryWP — Google Sheets Logger
=================================
Logs every scan result as a row in a Google Sheet.
Uses the Google Sheets API v4 with a Service Account.

Setup:
  1. Create a Google Cloud project
  2. Enable Google Sheets API
  3. Create a Service Account → download JSON key
  4. Share your Google Sheet with the service account email
  5. Add GSHEET_ID and GSHEET_CREDENTIALS (JSON key as string) to GitHub Secrets
"""

import os
import json
import urllib.request
import urllib.parse
import datetime


GSHEET_ID          = os.environ.get("GSHEET_ID", "")
GSHEET_CREDENTIALS = os.environ.get("GSHEET_CREDENTIALS", "")  # JSON string of service account key
SHEET_NAME         = "SentryWP Scans"


def _get_access_token(credentials: dict) -> str | None:
    """
    Get a short-lived OAuth2 access token from a service account JSON key.
    Uses JWT — no external library needed.
    """
    try:
        import base64
        import hmac
        import hashlib
        import time
        import struct

        # Build JWT
        header  = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=")
        now     = int(time.time())
        claims  = {
            "iss":   credentials["client_email"],
            "scope": "https://www.googleapis.com/auth/spreadsheets",
            "aud":   "https://oauth2.googleapis.com/token",
            "iat":   now,
            "exp":   now + 3600,
        }
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")

        # Sign with RSA private key using cryptography library
        from cryptography.hazmat.primitives         import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        private_key = serialization.load_pem_private_key(
            credentials["private_key"].encode(), password=None
        )
        signing_input = header + b"." + payload
        signature     = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        sig_encoded   = base64.urlsafe_b64encode(signature).rstrip(b"=")

        jwt_token = (signing_input + b"." + sig_encoded).decode()

        # Exchange JWT for access token
        token_data = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion":  jwt_token,
        }).encode()

        req = urllib.request.Request(
            "https://oauth2.googleapis.com/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            token_resp = json.loads(resp.read())
            return token_resp.get("access_token")

    except Exception as e:
        print(f"  [-] Google auth failed: {e}")
        return None


def log_to_sheet(result: dict) -> bool:
    """Append a scan result row to the Google Sheet."""
    if not GSHEET_ID or not GSHEET_CREDENTIALS:
        # Silently skip — Google Sheets is optional
        return False

    try:
        credentials = json.loads(GSHEET_CREDENTIALS)
    except json.JSONDecodeError:
        print("  [-] GSHEET_CREDENTIALS is not valid JSON")
        return False

    token = _get_access_token(credentials)
    if not token:
        return False

    ai          = result.get("ai") or {}
    flags       = result.get("scan_data") or {}
    total_flags = (
        len(flags.get("core_modifications", [])) +
        len(flags.get("suspicious_anomalies", [])) +
        len(flags.get("suspicious_uploads", []))
    )
    actions_taken = "; ".join(result.get("actions", []))[:500]

    row = [
        result.get("timestamp", ""),
        result.get("site_name", ""),
        result.get("url", ""),
        ai.get("severity", "unknown").upper(),
        f"{ai.get('confidence', 0):.0%}",
        ai.get("threat_type", ""),
        str(total_flags),
        ai.get("summary", "")[:500],
        actions_taken or "None",
        result.get("scan_mode", "quick"),
        "ERROR" if result.get("error") else "OK",
    ]

    url     = f"https://sheets.googleapis.com/v4/spreadsheets/{GSHEET_ID}/values/{urllib.parse.quote(SHEET_NAME)}:append"
    params  = "?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS"
    payload = json.dumps({"values": [row]}).encode("utf-8")

    try:
        req = urllib.request.Request(
            url + params,
            data=payload,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {token}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            print(f"  📊 Logged to Google Sheets: {result['site_name']} — {ai.get('severity','?').upper()}")
            return True
    except Exception as e:
        print(f"  [-] Google Sheets log failed: {e}")
        return False
