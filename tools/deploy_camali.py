import ftplib
import io
from pathlib import Path

TOOLS_DIR   = Path(__file__).parent.parent / "tools"
BRIDGE_FILE = TOOLS_DIR / "sentrywp_bridge.php"

with open(BRIDGE_FILE, "rb") as f:
    content = f.read()

print("[*] Uploading sentrywp_bridge.php to Camali Bijoux (217.21.65.126 / ftp.camalibijoux.com)...")
ftp = ftplib.FTP()
ftp.connect("217.21.65.126", 21, timeout=15)
ftp.login("u555150082.camalibijoux.com", "Q3@5IWcjljKH]:/i")
ftp.set_pasv(True)

files = []
ftp.retrlines("LIST", files.append)
print("Root files:")
for fl in files[:10]:
    print("  ", fl)

remote_path = "public_html/sentrywp_bridge.php"
if "public_html" not in [f.split()[-1] for f in files]:
    remote_path = "sentrywp_bridge.php"

print(f"[*] Uploading to {remote_path}...")
ftp.storbinary(f"STOR {remote_path}", io.BytesIO(content))
print("[+] Deployed bridge to Camali Bijoux successfully!")
ftp.quit()
