import urllib.request
import json

key = "AIzaSyDYOekbRGI0mIPHTscxn59Odyd5Gr5pWiQ"
url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"

try:
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
        print("[+] Available Models for key:")
        for m in data.get("models", []):
            name = m.get("name")
            methods = m.get("supportedGenerationMethods", [])
            if "generateContent" in methods:
                print("  •", name)
except Exception as e:
    print("[-] Error listing models:", e)
