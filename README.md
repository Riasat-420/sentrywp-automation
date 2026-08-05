# 🛡️ SentryWP Automation

> 24/7 automated WordPress security monitoring via GitHub Actions.
> Built by Muhammad Riasat Ali — Web Developer & WordPress Security Specialist.

## What This Does

Automatically scans all your client WordPress sites every 6 hours:
- Detects malware, backdoors, and modified core files
- Sends findings to Gemini AI for severity scoring
- Auto-fires the 5-Layer Security Defense on critical threats
- Sends instant Telegram alerts to your phone
- Emails PDF reports to clients every Sunday
- Logs all results to Google Sheets

---

## Project Structure

```
sentrywp-automation/
├── .github/workflows/
│   ├── scan-daily.yml          ← runs every 6h
│   └── weekly-report.yml       ← every Sunday
├── scanner/
│   ├── run_scan.py             ← main entry point
│   ├── ftp_handler.py          ← FTP + HTTP scanner runner
│   ├── ai_analysis.py          ← Gemini AI severity analysis
│   ├── autofix.py              ← 5-Layer Security auto-fix
│   ├── notify.py               ← Telegram + Email
│   ├── logger.py               ← Google Sheets logging
│   └── report.py               ← PDF report generator
├── tools/                      ← your existing security toolbox
│   ├── deep_scanner_v2.php
│   ├── db_scan.php
│   ├── delete_users.php
│   ├── fast_cleanup.php
│   ├── security-firewall-shield.php
│   ├── ftp_connect.py
│   └── generate_pdf.py
├── clients.json                ← add/remove client sites here
├── requirements.txt
└── .gitignore
```

---

## Setup Guide

### Step 1 — Fork / Clone this repo to your GitHub account

```bash
# Make it PRIVATE — it contains your toolbox scripts
```

### Step 2 — Add GitHub Secrets

Go to: **Repository → Settings → Secrets and variables → Actions → New repository secret**

#### Required secrets:

| Secret Name | Value |
|---|---|
| `GEMINI_API_KEY` | Your Google AI Studio API key |
| `TELEGRAM_BOT_TOKEN` | From @BotFather on Telegram |
| `TELEGRAM_CHAT_ID` | Your personal chat ID |
| `SITES_CONFIG` | JSON blob with all FTP credentials (see below) |

#### `SITES_CONFIG` format:
```json
{
  "kashmir_gems": {
    "ftp_host": "ftp.kashmirgems.com",
    "ftp_user": "u123456.ftp",
    "ftp_pass": "their_password"
  },
  "camali_bijoux": {
    "ftp_host": "ftp.camalibijoux.com",
    "ftp_user": "u980619603.mf",
    "ftp_pass": "their_password"
  }
}
```

#### Optional secrets (for full features):

| Secret Name | Purpose |
|---|---|
| `GSHEET_ID` | Google Sheets ID for scan history log |
| `GSHEET_CREDENTIALS` | Service account JSON (for Sheets API) |
| `SMTP_HOST` | SMTP server (e.g. smtp.gmail.com) |
| `SMTP_USER` | Email address to send reports from |
| `SMTP_PASS` | Email password / app password |

### Step 3 — Add Your Client Sites

Edit `clients.json`:
```json
[
  {
    "id": "your_client_id",          ← must match key in SITES_CONFIG
    "name": "Client Name",
    "url": "https://clientsite.com",
    "wp_root": "/",                  ← FTP path to WordPress root
    "notify_email": "client@email.com",
    "active": true
  }
]
```

### Step 4 — Enable GitHub Actions

Go to your repo → **Actions** tab → Enable workflows if prompted.

The scan will automatically start on the next scheduled run (every 6h).
To run immediately: **Actions → SentryWP Security Scan → Run workflow**.

---

## The 5-Layer Security Defense

| Layer | Tool | Triggers On |
|---|---|---|
| 1 — Root .htaccess Firewall | Built-in template | High + Critical |
| 2 — Uploads PHP Block | Built-in template | High + Critical |
| 3 — Permanent PHP Shield | `security-firewall-shield.php` | High + Critical |
| 4 — DB Audit & User Purge | `db_scan.php` | Critical only |
| 5 — File System Cleanup | Dynamic cleanup PHP | High + Critical |

---

## Telegram Setup (5 minutes)

1. Open Telegram → search **@BotFather**
2. Send `/newbot` → follow prompts → copy the **Bot Token**
3. Start a chat with your bot → send any message
4. Open: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
5. Find your `chat_id` in the response
6. Add both as GitHub Secrets

---

## Getting a Gemini API Key (Free)

1. Go to [aistudio.google.com](https://aistudio.google.com)
2. Sign in with Google
3. Click **Get API Key** → Create API key
4. Add as `GEMINI_API_KEY` in GitHub Secrets

---

## Monthly Cost

| Item | Cost |
|---|---|
| GitHub Actions | **FREE** |
| Gemini 1.5 Flash | ~$0.30/mo for 1000 scans |
| Telegram alerts | **FREE** |
| Google Sheets logging | **FREE** |
| **Total** | **~$0.30/mo** |

---

*SentryWP — Built by Muhammad Riasat Ali*
