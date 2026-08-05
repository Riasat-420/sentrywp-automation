import urllib.request
import urllib.parse
import json

url = "https://digitalmarketergurus.com/sentrywp_bridge.php"
payload = urllib.parse.urlencode({
    "token": "SWP-Br1dge-S3cr3t-K3y-2026",
    "action": "ping"
}).encode("utf-8")

req = urllib.request.Request(url, data=payload, method="POST")
req.add_header("Content-Type", "application/x-www-form-urlencoded")

try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        res = resp.read().decode("utf-8")
        print("[+] HTTP Ping successful!")
        print("Response:", res)
except Exception as e:
        print("[-] Ping error:", e)
