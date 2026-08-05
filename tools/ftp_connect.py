import os
import sys
import ftplib
import argparse

class FTPToolbox:
    def __init__(self, host, user, passwd, port=21, secure=False):
        self.host = host
        self.user = user
        self.passwd = passwd
        self.port = int(port)
        self.secure = secure
        self.ftp = None

    def connect(self):
        try:
            print(f"[*] Connecting to {self.host}:{self.port} (Secure: {self.secure})...")
            if self.secure:
                self.ftp = ftplib.FTP_TLS()
            else:
                self.ftp = ftplib.FTP()
            
            self.ftp.connect(self.host, self.port, timeout=30)
            self.ftp.login(self.user, self.passwd)
            self.ftp.set_pasv(True)
            
            if self.secure:
                self.ftp.prot_p() # secure data connection
                
            print(f"[+] Successfully connected to {self.host}!")
            print(f"[+] Remote System Type: {self.ftp.sendcmd('SYST')}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False

    def list_dir(self, path="."):
        try:
            print(f"[*] Listing contents of remote path: {path}")
            files = []
            self.ftp.retrlines(f'LIST {path}', files.append)
            for f in files:
                print(f"  {f}")
            return files
        except Exception as e:
            print(f"[-] Failed to list directory: {e}")
            return []

    def upload_file(self, local_path, remote_path):
        if not os.path.exists(local_path):
            print(f"[-] Local file not found: {local_path}")
            return False
        
        try:
            print(f"[*] Uploading local '{local_path}' to remote '{remote_path}'...")
            with open(local_path, 'rb') as f:
                self.ftp.storbinary(f'STOR {remote_path}', f)
            print("[+] Upload complete!")
            return True
        except Exception as e:
            print(f"[-] Failed to upload file: {e}")
            return False

    def download_file(self, remote_path, local_path):
        try:
            print(f"[*] Downloading remote '{remote_path}' to local '{local_path}'...")
            with open(local_path, 'wb') as f:
                self.ftp.retrbinary(f'RETR {remote_path}', f.write)
            print("[+] Download complete!")
            return True
        except Exception as e:
            print(f"[-] Failed to download file: {e}")
            if os.path.exists(local_path):
                os.remove(local_path)
            return False

    def delete_file(self, remote_path):
        try:
            print(f"[*] Deleting remote file: {remote_path}")
            self.ftp.delete(remote_path)
            print("[+] File deleted successfully!")
            return True
        except Exception as e:
            print(f"[-] Failed to delete remote file: {e}")
            return False

    def close(self):
        if self.ftp:
            try:
                self.ftp.quit()
            except:
                self.ftp.close()
            print("[*] FTP connection closed.")

def main():
    parser = argparse.ArgumentParser(description="Multi-Purpose FTP Connection & Security Deployment Utility")
    parser.add_argument("--host", required=True, help="FTP Host Server Address")
    parser.add_argument("--user", required=True, help="FTP Username")
    parser.add_argument("--passwd", required=True, help="FTP Password")
    parser.add_argument("--port", default=21, type=int, help="FTP Port (default: 21)")
    parser.add_argument("--secure", action="store_true", help="Use secure FTPS (FTP over TLS)")
    
    # Operations
    parser.add_argument("--test", action="store_true", help="Test remote server connection")
    parser.add_argument("--list", nargs="?", const=".", help="List contents of a remote directory path")
    parser.add_argument("--upload", nargs=2, metavar=("LOCAL", "REMOTE"), help="Upload local file to remote path")
    parser.add_argument("--download", nargs=2, metavar=("REMOTE", "LOCAL"), help="Download remote file to local path")
    parser.add_argument("--delete", metavar="REMOTE", help="Delete a file on the remote server")

    args = parser.parse_args()

    client = FTPToolbox(args.host, args.user, args.passwd, args.port, args.secure)
    if not client.connect():
        sys.exit(1)

    try:
        if args.test:
            print("[+] Diagnostic verification successful!")
        elif args.list is not None:
            client.list_dir(args.list)
        elif args.upload:
            client.upload_file(args.upload[0], args.upload[1])
        elif args.download:
            client.download_file(args.download[0], args.download[1])
        elif args.delete:
            client.delete_file(args.delete)
        else:
            print("[*] No operation specified. Use --help to view available commands.")
            client.list_dir(".")
    finally:
        client.close()

if __name__ == "__main__":
    main()
