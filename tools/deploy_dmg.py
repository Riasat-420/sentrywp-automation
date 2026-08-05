import ftplib
import io
from pathlib import Path

TOOLS_DIR   = Path(__file__).parent.parent / "tools"
BRIDGE_FILE = TOOLS_DIR / "sentrywp_bridge.php"

with open(BRIDGE_FILE, "rb") as f:
    content = f.read()

print("[*] Uploading sentrywp_bridge.php to Digital Marketer Gurus root...")
ftp = ftplib.FTP()
ftp.connect("147.93.92.41", 21, timeout=15)
ftp.login("u612817574.digitalmarketergurus.com", "O=oBM+:L5;n2*3o|")
ftp.set_pasv(True)

ftp.storbinary("STOR sentrywp_bridge.php", io.BytesIO(content))
print("[+] Deployed to Digital Marketer Gurus successfully!")
ftp.quit()
