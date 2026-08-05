import urllib.request
import json

key = "AIzaSyDYOekbRGI0mIPHTscxn59Odyd5Gr5pWiQ"
models = [
    "gemini-1.5-flash",
    "gemini-2.0-flash",
    "gemini-2.5-flash",
    "gemini-1.5-pro"
]

for m in models:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={key}"
    payload = json.dumps({
        "contents": [{"parts": [{"text": "Hello, respond with JSON: {\"status\": \"ok\"}"}]}]
    }).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            print(f"[+] Model '{m}' SUCCESS!")
            print("Response:", data["candidates"][0]["content"]["parts"][0]["text"])
            break
    except Exception as e:
        print(f"[-] Model '{m}' failed: {e}")
