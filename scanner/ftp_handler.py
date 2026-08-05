"""
SentryWP — FTP Handler
=======================
Wraps the existing FTPToolbox class with extra methods needed by the automation:
- HTTP GET to run the PHP scanner and collect JSON output
- Upload/delete helpers with cleaner return values
"""

import os
import sys
import ftplib
import urllib.request
import urllib.error
import ssl
import json
import time
from pathlib import Path


class FTPHandler:
    def __init__(self, host: str, user: str, passwd: str, port: int = 21, secure: bool = False):
        self.host   = host
        self.user   = user
        self.passwd = passwd
        self.port   = port
        self.secure = secure
        self.ftp    = None

    def connect(self) -> bool:
        try:
            if self.secure:
                self.ftp = ftplib.FTP_TLS()
            else:
                self.ftp = ftplib.FTP()

            self.ftp.connect(self.host, self.port, timeout=30)
            self.ftp.login(self.user, self.passwd)
            self.ftp.set_pasv(True)

            if self.secure:
                self.ftp.prot_p()

            return True
        except Exception as e:
            print(f"  [-] FTP connect failed: {e}")
            return False

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        try:
            with open(local_path, "rb") as f:
                self.ftp.storbinary(f"STOR {remote_path}", f)
            return True
        except Exception as e:
            print(f"  [-] Upload failed ({remote_path}): {e}")
            return False

    def upload_string(self, content: str, remote_path: str) -> bool:
        """Upload a string directly as a file (no temp file needed)."""
        import io
        try:
            buf = io.BytesIO(content.encode("utf-8"))
            self.ftp.storbinary(f"STOR {remote_path}", buf)
            return True
        except Exception as e:
            print(f"  [-] Upload string failed ({remote_path}): {e}")
            return False

    def download_to_string(self, remote_path: str) -> str | None:
        import io
        try:
            buf = io.BytesIO()
            self.ftp.retrbinary(f"RETR {remote_path}", buf.write)
            return buf.getvalue().decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"  [-] Download failed ({remote_path}): {e}")
            return None

    def delete_file(self, remote_path: str) -> bool:
        try:
            self.ftp.delete(remote_path)
            return True
        except Exception:
            return False

    def http_get_json(self, url: str, retries: int = 3, delay: int = 3) -> dict | None:
        """
        Make an HTTP GET request to run the uploaded PHP scanner.
        Returns parsed JSON dict or None on failure.
        Ignores SSL errors (self-signed certs on some shared hosts).
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        for attempt in range(1, retries + 1):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "SentryWP-Scanner/2.0"},
                )
                with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore").strip()
                    # The scanner may output some PHP warnings before the JSON
                    # Find the first '{' to strip any leading noise
                    json_start = raw.find("{")
                    if json_start > 0:
                        raw = raw[json_start:]
                    return json.loads(raw)
            except urllib.error.HTTPError as e:
                print(f"  [-] HTTP {e.code} on attempt {attempt}: {url}")
            except urllib.error.URLError as e:
                print(f"  [-] URL error on attempt {attempt}: {e.reason}")
            except json.JSONDecodeError as e:
                print(f"  [-] JSON parse error: {e}")
                return None
            except Exception as e:
                print(f"  [-] HTTP attempt {attempt} failed: {e}")

            if attempt < retries:
                time.sleep(delay)

        return None

    def close(self):
        if self.ftp:
            try:
                self.ftp.quit()
            except Exception:
                try:
                    self.ftp.close()
                except Exception:
                    pass
