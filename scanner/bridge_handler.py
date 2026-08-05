"""
SentryWP — HTTP Bridge Handler
================================
Communicates with sentrywp_bridge.php on the target site via HTTPS POST.
No FTP from GitHub Actions needed — all communication is HTTP only.
"""

import os
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
import time
from pathlib import Path


BRIDGE_SECRET = os.environ.get("SENTRYWP_BRIDGE_SECRET", "SWP-Br1dge-S3cr3t-K3y-2026")


def _post(url: str, data: dict, retries: int = 3, delay: int = 3) -> dict | None:
    """Send HTTPS POST to bridge, return parsed JSON or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    payload = urllib.parse.urlencode(data).encode("utf-8")

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type":       "application/x-www-form-urlencoded",
                    "X-SentryWP-Token":   BRIDGE_SECRET,
                    "User-Agent":         "SentryWP-Scanner/2.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
                raw = resp.read().decode("utf-8", errors="ignore").strip()
                json_start = raw.find("{")
                if json_start > 0:
                    raw = raw[json_start:]
                return json.loads(raw)

        except urllib.error.HTTPError as e:
            print(f"  [-] Bridge HTTP {e.code} on attempt {attempt}: {url}")
        except json.JSONDecodeError as e:
            print(f"  [-] Bridge JSON parse error: {e}")
            return None
        except Exception as e:
            print(f"  [-] Bridge attempt {attempt} failed: {e}")

        if attempt < retries:
            time.sleep(delay)

    return None


class BridgeHandler:
    def __init__(self, site_url: str):
        self.site_url    = site_url.rstrip("/")
        self.bridge_url  = f"{self.site_url}/sentrywp_bridge.php"
        self.secret      = BRIDGE_SECRET

    def _post(self, action: str, extra: dict = None) -> dict | None:
        data = {"token": self.secret, "action": action}
        if extra:
            data.update(extra)
        return _post(self.bridge_url, data)

    def ping(self) -> bool:
        """Verify bridge is reachable and authenticated."""
        result = self._post("ping")
        if result and result.get("status") == "ok":
            print(f"  ✅ Bridge connected — WP root: {result.get('wp_root', '?')}")
            return True
        print(f"  [-] Bridge ping failed: {result}")
        return False

    def scan(self) -> dict | None:
        """Run the full malware scanner via bridge (Layer 5)."""
        return self._post("scan")

    def harden(self) -> dict | None:
        """Deploy .htaccess security rules via bridge (Layers 1 & 2)."""
        return self._post("harden")

    def deploy_shield(self, shield_content: str) -> dict | None:
        """Deploy PHP firewall shield to mu-plugins via bridge (Layer 3)."""
        return self._post("shield", {"shield_content": shield_content})

    def cleanup(self, files: list) -> dict | None:
        """Delete confirmed malicious files via bridge (Layer 5)."""
        return self._post("cleanup", {"files": json.dumps(files)})
