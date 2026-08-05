import urllib.request
import urllib.parse
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

url = "https://camalibijoux.com/sentrywp_bridge.php"

print("[*] Fetching https://camalibijoux.com/sentrywp_bridge.php ...")
try:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        print("Status:", resp.status)
        print("Body:", resp.read().decode("utf-8", errors="ignore")[:300])
except urllib.error.HTTPError as e:
    print("HTTP Error:", e.code)
    print("Body:", e.read().decode("utf-8", errors="ignore")[:300])
except Exception as e:
    print("Error:", e)
