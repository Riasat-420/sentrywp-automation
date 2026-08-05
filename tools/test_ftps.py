import ftplib

print("[*] Testing FTPS connection to Camali Bijoux...")
try:
    ftp = ftplib.FTP_TLS()
    ftp.connect("82.180.172.16", 21, timeout=30)
    ftp.login("u555150082.camalibijoux.com", "Q3@5IWcjljKH]:/i")
    ftp.prot_p()
    print("[+] FTPS Connection Successful!")

    files = []
    ftp.retrlines("LIST", files.append)
    print("Files in root:")
    for f in files[:10]:
        print("  ", f)
    ftp.quit()
except Exception as e:
    print(f"[-] FTPS error: {e}")
