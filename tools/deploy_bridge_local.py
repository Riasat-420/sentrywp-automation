"""
Deploy sentrywp_bridge.php to client sites via local FTP
"""

import ftplib
import os
import sys
from pathlib import Path

TOOLS_DIR   = Path(__file__).parent.parent / "tools"
BRIDGE_FILE = TOOLS_DIR / "sentrywp_bridge.php"

SITES = [
    {
        "name": "Camali Bijoux",
        "host": "82.180.172.16",
        "user": "u555150082.camalibijoux.com",
        "pass": "Q3@5IWcjljKH]:/i",
        "wp_root": "public_html",
    },
    {
        "name": "Digital Marketer Gurus",
        "host": "147.93.92.41",
        "user": "u612817574.digitalmarketergurus.com",
        "pass": "O=oBM+:L5;n2*3o|",
        "wp_root": "public_html",
    }
]

def main():
    if not BRIDGE_FILE.exists():
        print(f"[-] Missing bridge file: {BRIDGE_FILE}")
        sys.exit(1)

    with open(BRIDGE_FILE, "rb") as f:
        content = f.read()

    for site in SITES:
        print(f"\n[*] Connecting to {site['name']} ({site['host']})...")
        try:
            ftp = ftplib.FTP()
            ftp.connect(site["host"], 21, timeout=30)
            ftp.login(site["user"], site["pass"])
            ftp.set_pasv(True)

            remote_path = f"{site['wp_root'].rstrip('/')}/sentrywp_bridge.php"
            print(f"[*] Uploading to {remote_path}...")

            import io
            ftp.storbinary(f"STOR {remote_path}", io.BytesIO(content))
            print(f"[+] Successfully deployed bridge to {site['name']}!")
            ftp.quit()
        except Exception as e:
            print(f"[-] Failed for {site['name']}: {e}")

if __name__ == "__main__":
    main()
