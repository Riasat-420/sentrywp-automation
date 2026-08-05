"""
SentryWP — AI Analysis Module (Gemini)
=======================================
Sends scan findings to Gemini 1.5 Flash and gets back:
  - severity:    clean | low | medium | high | critical
  - confidence:  0.0 – 1.0
  - threat_type: description of what was found
  - summary:     human-readable explanation
  - remediation: what to do
  - triggers:    which security layers to auto-fire
"""

import os
import json
import urllib.request
import urllib.error


GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_URL     = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-1.5-flash:generateContent?key={key}"
)


def _build_prompt(site_name: str, scan_data: dict) -> str:
    core_mods   = scan_data.get("core_modifications", [])
    anomalies   = scan_data.get("suspicious_anomalies", [])
    bad_uploads = scan_data.get("suspicious_uploads", [])

    # Limit snippet size to avoid token overflow
    def truncate_list(lst, max_items=10):
        return lst[:max_items]

    findings_json = json.dumps({
        "core_modifications": truncate_list(core_mods),
        "suspicious_anomalies": truncate_list(anomalies),
        "suspicious_uploads": truncate_list(bad_uploads),
    }, indent=2)

    return f"""You are SentryWP, an expert WordPress malware analysis AI.

A security scan of the WordPress site "{site_name}" has produced the following findings.
Analyse them and respond ONLY with a valid JSON object — no markdown, no explanation outside the JSON.

FINDINGS:
{findings_json}

Respond with this exact JSON structure:
{{
  "severity": "<clean|low|medium|high|critical>",
  "confidence": <float 0.0-1.0>,
  "threat_type": "<one-line description of the threat category>",
  "summary": "<2-3 sentence human-readable explanation of what was found>",
  "remediation": "<what actions should be taken>",
  "triggers": <array of security layers to fire, e.g. ["layer_1_htaccess", "layer_2_uploads_block", "layer_3_shield", "layer_4_db_purge", "layer_5_file_cleanup"]>,
  "false_positive_risk": "<low|medium|high — how likely some findings are false positives>"
}}

Rules:
- "clean": zero real threats, all findings are likely false positives
- "low": minor suspicious patterns, no confirmed malware
- "medium": likely malware but low confidence, alert only, do not auto-delete
- "high": confirmed malware patterns, auto-fix recommended
- "critical": active webshell/backdoor confirmed, immediate auto-fix required
"""


def analyse_with_gemini(site_name: str, scan_data: dict) -> dict:
    """
    Call Gemini API with scan findings.
    Returns a dict with severity, confidence, summary, etc.
    Falls back to a safe 'manual_review' result on any error.
    """
    fallback = {
        "severity":           "medium",
        "confidence":         0.5,
        "threat_type":        "Unknown (AI analysis failed)",
        "summary":            "AI analysis could not complete. Manual review required.",
        "remediation":        "Review scan findings manually.",
        "triggers":           [],
        "false_positive_risk": "unknown",
    }

    if not GEMINI_API_KEY:
        print("  ⚠️  GEMINI_API_KEY not set — skipping AI analysis, defaulting to medium severity")
        return fallback

    prompt  = _build_prompt(site_name, scan_data)
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature":     0.1,
            "maxOutputTokens": 1024,
        },
    }

    try:
        url     = GEMINI_URL.format(key=GEMINI_API_KEY)
        data    = json.dumps(payload).encode("utf-8")
        req     = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            body     = json.loads(resp.read().decode("utf-8"))
            raw_text = body["candidates"][0]["content"]["parts"][0]["text"].strip()

            # Strip markdown fences if Gemini wraps in ```json
            if raw_text.startswith("```"):
                raw_text = raw_text.split("```")[1]
                if raw_text.startswith("json"):
                    raw_text = raw_text[4:]

            ai_result = json.loads(raw_text)
            return ai_result

    except urllib.error.HTTPError as e:
        print(f"  [-] Gemini API HTTP error: {e.code} — {e.read().decode()[:200]}")
    except json.JSONDecodeError as e:
        print(f"  [-] Gemini returned invalid JSON: {e}")
    except Exception as e:
        print(f"  [-] Gemini API error: {e}")

    return fallback
