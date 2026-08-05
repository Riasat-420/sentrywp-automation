import ftplib

for p in ["Q3@5IWcjljKH]:/i", "z/T$PJBMmLaNfGR0"]:
    for u in ["u555150082.camalibijoux.com", "u555150082.mf", "u555150082"]:
        try:
            ftp = ftplib.FTP_TLS()
            ftp.connect("82.180.172.16", 21, timeout=10)
            ftp.login(u, p)
            ftp.prot_p()
            print(f"[+] FTPS SUCCESS! u={u}, p={p}")
            ftp.quit()
        except Exception as e:
            print(f"[-] u={u}, p={p} -> {e}")
