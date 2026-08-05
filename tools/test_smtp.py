import smtplib
import ssl
from email.mime.text import MIMEText

host = "smtp.hostinger.com"
port = 465
user = "developers@allatifsofts.com"
passwd = "Allatif@123"
to_email = "muhammadriasatali40@gmail.com"

print(f"[*] Testing Hostinger SMTP connection to {host}:{port}...")

msg = MIMEText("This is a test email from SentryWP Automation.", "plain")
msg["Subject"] = "SentryWP SMTP Test Alert"
msg["From"] = user
msg["To"] = to_email

try:
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as server:
        server.login(user, passwd)
        server.sendmail(user, to_email, msg.as_string())
    print("[+] Test email SENT successfully to", to_email)
except Exception as e:
    print("[-] SMTP failed:", e)
