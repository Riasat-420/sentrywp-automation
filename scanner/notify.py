"""
SentryWP — Notification Module
================================
Supports:
  • Telegram Bot (free, instant alerts)
  • WhatsApp via UltraMsg (~$15/mo flat)
  • Email via Gmail SMTP (PDF report delivery)

All credentials come from GitHub Secrets — nothing hardcoded.
"""

import os
import json
import urllib.request
import urllib.parse
import urllib.error
import smtplib
import ssl
from email.mime.text        import MIMEText
from email.mime.multipart   import MIMEMultipart
from email.mime.application import MIMEApplication
from pathlib import Path


# ─── Credentials from GitHub Secrets ─────────────────────────────────────────

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")

# UltraMsg WhatsApp
ULTRAMSG_INSTANCE  = os.environ.get("ULTRAMSG_INSTANCE", "")   # e.g. instance12345
ULTRAMSG_TOKEN     = os.environ.get("ULTRAMSG_TOKEN", "")       # API token
WHATSAPP_NUMBER    = os.environ.get("WHATSAPP_NUMBER", "")      # e.g. 923001234567

# SMTP Credentials (Hostinger or Gmail)
def _get_clean_env(key: str, default: str = "") -> str:
    val = os.environ.get(key, default).strip().strip('"').strip("'")
    if "://" in val:
        val = val.split("://")[-1].split("/")[0]
    return val

SMTP_HOST = _get_clean_env("SMTP_HOST", "smtp.hostinger.com")
try:
    SMTP_PORT = int(_get_clean_env("SMTP_PORT", "465"))
except ValueError:
    SMTP_PORT = 465

SMTP_USER = _get_clean_env("SMTP_USER", "")
SMTP_PASS = _get_clean_env("SMTP_PASS", "")


# ─── Severity → Emoji mapping ─────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "clean":    "✅",
    "low":      "🟡",
    "medium":   "🟠",
    "high":     "🔴",
    "critical": "🚨",
    "unknown":  "❓",
}


def _format_telegram_message(result: dict) -> str:
    ai        = result.get("ai") or {}
    severity  = ai.get("severity", "unknown")
    emoji     = SEVERITY_EMOJI.get(severity, "❓")
    actions   = result.get("actions", [])
    flags     = result.get("scan_data") or {}
    total_flags = (
        len(flags.get("core_modifications", [])) +
        len(flags.get("suspicious_anomalies", [])) +
        len(flags.get("suspicious_uploads", []))
    )

    lines = [
        f"{emoji} *SentryWP Alert*",
        f"",
        f"🌐 *Site:* {result['site_name']}",
        f"🔗 `{result['url']}`",
        f"",
        f"🎯 *Severity:* `{severity.upper()}`",
        f"📊 *Confidence:* `{ai.get('confidence', 0):.0%}`",
        f"🦠 *Threat:* {ai.get('threat_type', 'N/A')}",
        f"🚩 *Flags found:* {total_flags}",
        f"",
        f"📝 *Summary:*",
        f"{ai.get('summary', 'No summary available.')}",
    ]

    if actions and actions != ["alert_only"]:
        lines += [
            f"",
            f"🔧 *Auto-fix actions taken:* {len(actions)}",
        ]
        for a in actions[:5]:  # show max 5 actions
            lines.append(f"  • {a[:80]}")
    elif actions == ["alert_only"]:
        lines += [
            f"",
            f"⚠️ *Manual review required* — auto-fix was NOT triggered (medium severity)",
        ]

    lines += [
        f"",
        f"🕐 `{result['timestamp']} UTC`",
        f"",
        f"_SentryWP Automation by Muhammad Riasat Ali_",
    ]

    return "\n".join(lines)


def send_telegram_alert(result: dict) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("  ⚠️  Telegram not configured (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID missing)")
        return False

    message = _format_telegram_message(result)
    url     = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    payload = json.dumps({
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       message,
        "parse_mode": "Markdown",
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
            if body.get("ok"):
                print(f"  📱 Telegram alert sent for {result['site_name']}")
                return True
            else:
                print(f"  [-] Telegram API error: {body}")
                return False
    except Exception as e:
        print(f"  [-] Telegram send failed: {e}")
        return False


def send_whatsapp_alert(result: dict) -> bool:
    """Send WhatsApp alert via UltraMsg API."""
    if not ULTRAMSG_INSTANCE or not ULTRAMSG_TOKEN or not WHATSAPP_NUMBER:
        print("  ⚠️  WhatsApp not configured (ULTRAMSG_INSTANCE / ULTRAMSG_TOKEN / WHATSAPP_NUMBER missing)")
        return False

    ai       = result.get("ai") or {}
    severity = ai.get("severity", "unknown").upper()
    emoji    = SEVERITY_EMOJI.get(severity.lower(), "❓")

    # WhatsApp plain text (no Markdown)
    actions_count = len([a for a in result.get("actions", []) if a != "alert_only"])
    message = (
        f"{emoji} *SentryWP Alert*\n\n"
        f"Site: {result['site_name']}\n"
        f"URL: {result['url']}\n"
        f"Severity: {severity}\n"
        f"Confidence: {ai.get('confidence', 0):.0%}\n"
        f"Threat: {ai.get('threat_type', 'N/A')}\n\n"
        f"{ai.get('summary', '')}\n\n"
        f"{'Auto-fix deployed: ' + str(actions_count) + ' actions taken' if actions_count else 'Manual review required'}\n\n"
        f"Time: {result['timestamp']} UTC\n"
        f"- SentryWP by Muhammad Riasat Ali"
    )

    url     = f"https://api.ultramsg.com/{ULTRAMSG_INSTANCE}/messages/chat"
    payload = urllib.parse.urlencode({
        "token":  ULTRAMSG_TOKEN,
        "to":     WHATSAPP_NUMBER,
        "body":   message,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
            if body.get("sent") == "true" or body.get("id"):
                print(f"  💬 WhatsApp alert sent for {result['site_name']}")
                return True
            else:
                print(f"  [-] UltraMsg error: {body}")
                return False
    except Exception as e:
        print(f"  [-] WhatsApp send failed: {e}")
        return False


def send_instant_email_alert(result: dict, client: dict = None) -> bool:
    """Send instant email alert when threat is detected."""
    if not SMTP_USER or not SMTP_PASS:
        print("  ⚠️  Email alert not configured (SMTP_USER / SMTP_PASS missing)")
        return False

    to_email = (client.get("notify_email") if client else None) or "muhammadriasatali40@gmail.com"
    site_name = result.get("site_name", "WordPress Site")
    ai        = result.get("ai") or {}
    severity  = ai.get("severity", "unknown").upper()
    actions   = result.get("actions", [])

    subject = f"🚨 SentryWP Threat Alert [{severity}] — {site_name}"
    body_text = f"""SentryWP Security Threat Alert
====================================
Site: {site_name} ({result.get('url', '')})
Status/Severity: {severity}
AI Confidence: {ai.get('confidence', 0):.0%}
Threat Description: {ai.get('threat_type', 'Malware / Code Anomaly Detected')}

Summary:
{ai.get('summary', 'No detailed summary provided.')}

Actions Taken:
{chr(10).join(['  • ' + str(a) for a in actions]) if actions else '  • Manual Review Required (Medium Severity)'}

Timestamp: {result.get('timestamp', '')} UTC

--
SentryWP Automation by Muhammad Riasat Ali
Web Developer & WordPress Security Specialist
"""

    msg = MIMEMultipart()
    msg["From"]    = SMTP_USER
    msg["To"]      = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body_text, "plain"))

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=15) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
        print(f"  📧 Instant threat alert emailed to {to_email}")
        return True
    except Exception as e:
        print(f"  [-] Email send failed: {e}")
        return False


def send_all_alerts(result: dict, client: dict = None) -> None:
    """
    Fire all configured notification channels simultaneously.
    Telegram + WhatsApp + Email all send if credentials are set.
    Either one failing does NOT block the others.
    """
    ai       = result.get("ai") or {}
    severity = ai.get("severity", "unknown")

    if severity == "clean":
        return  # Silent on clean scans

    send_telegram_alert(result)
    send_whatsapp_alert(result)
    send_instant_email_alert(result, client)


def send_email_report(pdf_path: Path, client: dict, result: dict) -> bool:
    """Send the weekly PDF report to the client via email."""
    if not SMTP_USER or not SMTP_PASS:
        print("  ⚠️  Email not configured (SMTP_USER / SMTP_PASS missing)")
        return False

    to_email    = client.get("notify_email", "")
    site_name   = client["name"]
    ai          = result.get("ai") or {}
    severity    = ai.get("severity", "unknown")

    subject = f"SentryWP Weekly Security Report — {site_name}"
    if severity in ("high", "critical"):
        subject = f"🚨 SentryWP SECURITY ALERT — {site_name}"

    body_text = f"""Dear {site_name} Team,

Please find attached your SentryWP weekly security report.

Summary:
  Site: {result['url']}
  Scan Date: {result['timestamp']} UTC
  Overall Status: {severity.upper()}
  AI Summary: {ai.get('summary', 'N/A')}

This report was automatically generated by SentryWP Automation.

Best regards,
Muhammad Riasat Ali
Web Developer & WordPress Security Specialist
"""

    msg = MIMEMultipart()
    msg["From"]    = SMTP_USER
    msg["To"]      = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body_text, "plain"))

    # Attach PDF
    if pdf_path and Path(pdf_path).exists():
        with open(pdf_path, "rb") as f:
            part = MIMEApplication(f.read(), Name=Path(pdf_path).name)
            part["Content-Disposition"] = f'attachment; filename="{Path(pdf_path).name}"'
            msg.attach(part)

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
        print(f"  📧 Report emailed to {to_email}")
        return True
    except Exception as e:
        print(f"  [-] Email send failed: {e}")
        return False
