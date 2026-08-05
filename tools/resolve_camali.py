import socket
import ftplib

for host_name in ["camalibijoux.com", "ftp.camalibijoux.com", "82.180.172.16"]:
    try:
        ip = socket.gethostbyname(host_name)
        print(f"[*] Host: {host_name} -> Resolved IP: {ip}")
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, 21, timeout=10)
            res = ftp.login("u555150082.camalibijoux.com", "Q3@5IWcjljKH]:/i")
            print(f"  [+] Plain FTP Login SUCCESS on {host_name} ({ip}): {res}")
            ftp.quit()
        except Exception as e1:
            print(f"  [-] Plain FTP failed on {host_name} ({ip}): {e1}")
            try:
                ftp = ftplib.FTP_TLS()
                ftp.connect(ip, 21, timeout=10)
                res = ftp.login("u555150082.camalibijoux.com", "Q3@5IWcjljKH]:/i")
                ftp.prot_p()
                print(f"  [+] FTPS Login SUCCESS on {host_name} ({ip}): {res}")
                ftp.quit()
            except Exception as e2:
                print(f"  [-] FTPS failed on {host_name} ({ip}): {e2}")
    except Exception as e:
        print(f"[-] Could not resolve {host_name}: {e}")
