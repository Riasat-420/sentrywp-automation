import ftplib

def test_site(name, host, user, passwd):
    print(f"\n--- Testing {name} ---")
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 21, timeout=15)
        ftp.login(user, passwd)
        ftp.set_pasv(True)
        print(f"[+] Login successful on {name}!")
        files = []
        ftp.retrlines("LIST", files.append)
        print("  Current dir files:")
        for f in files[:10]:
            print("   ", f)
        ftp.quit()
    except Exception as e:
        print(f"[-] Error on {name}: {e}")

test_site("Camali Bijoux", "82.180.172.16", "u555150082.camalibijoux.com", "Q3@5IWcjljKH]:/i")
test_site("Digital Marketer Gurus", "147.93.92.41", "u612817574.digitalmarketergurus.com", "O=oBM+:L5;n2*3o|")
