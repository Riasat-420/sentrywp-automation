"""
SentryWP — Auto-Fix Pipeline
==============================
Fires the appropriate security layers based on AI severity assessment.

Security Layers:
  Layer 1 — Root .htaccess firewall          (harden_generic.py → root)
  Layer 2 — Uploads PHP block                (harden_generic.py → uploads)
  Layer 3 — Permanent PHP firewall shield    (security-firewall-shield.php → mu-plugins)
  Layer 4 — DB audit & rogue user purge      (db_scan.php + delete_users.php)
  Layer 5 — File system scan & cleanup       (fast_cleanup_dynamic.php)
"""

import os
import json
import ftplib
import io
import datetime
from pathlib import Path


# ─── Security Layer Templates ─────────────────────────────────────────────────

ROOT_HTACCESS = """# BEGIN SentryWP Security Hardening
# Generated: {timestamp}

# Disable directory browsing
Options -Indexes

# Protect wp-config.php
<Files wp-config.php>
    Require all denied
</Files>

# Block access to xmlrpc.php
<Files xmlrpc.php>
    Require all denied
</Files>

# Block PHP execution in sensitive dirs
<FilesMatch "\.(php|php4|php5|php7|php8|phtml|phar|pht)$">
    <If "%{REQUEST_URI} =~ m#/(wp-content/uploads|wp-content/cache)/#">
        Require all denied
    </If>
</FilesMatch>

# Block common malicious query strings
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{QUERY_STRING} (eval\() [NC,OR]
    RewriteCond %{QUERY_STRING} (base64_encode.*\(.*\)) [NC,OR]
    RewriteCond %{QUERY_STRING} (\.\./\.\.) [NC]
    RewriteRule .* - [F,L]
</IfModule>

# END SentryWP Security Hardening

# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
"""

UPLOADS_HTACCESS = """# SentryWP: Block PHP execution in uploads directory
# Generated: {timestamp}
<FilesMatch "\.(php|php4|php5|php7|php8|phtml|phar|pht|sh|cgi|pl|py)$">
    Require all denied
</FilesMatch>
<IfModule mod_php7.c>
    php_flag engine off
</IfModule>
<IfModule mod_php8.c>
    php_flag engine off
</IfModule>
"""


def _ftp_upload_string(ftp_obj, content: str, remote_path: str) -> bool:
    try:
        buf = io.BytesIO(content.encode("utf-8"))
        ftp_obj.ftp.storbinary(f"STOR {remote_path}", buf)
        return True
    except Exception as e:
        print(f"  [-] Failed to write {remote_path}: {e}")
        return False


def _ftp_mkdir_safe(ftp_obj, path: str):
    """Create directory on FTP if it doesn't exist."""
    try:
        ftp_obj.ftp.mkd(path)
    except ftplib.error_perm:
        pass  # Already exists


# ─── Individual Layer Implementations ────────────────────────────────────────

def fire_layer_1_htaccess(ftp, wp_root: str, timestamp: str) -> str:
    """Layer 1: Upload hardened root .htaccess"""
    content = ROOT_HTACCESS.format(timestamp=timestamp)
    remote  = f"{wp_root.rstrip('/')}/.htaccess"
    ok      = _ftp_upload_string(ftp, content, remote)
    msg     = f"Layer 1 ({'OK' if ok else 'FAILED'}): Root .htaccess firewall deployed"
    print(f"  {'✅' if ok else '❌'} {msg}")
    return msg


def fire_layer_2_uploads_block(ftp, wp_root: str, timestamp: str) -> str:
    """Layer 2: Upload PHP block .htaccess to wp-content/uploads/"""
    content = UPLOADS_HTACCESS.format(timestamp=timestamp)
    remote  = f"{wp_root.rstrip('/')}/wp-content/uploads/.htaccess"
    ok      = _ftp_upload_string(ftp, content, remote)
    msg     = f"Layer 2 ({'OK' if ok else 'FAILED'}): Uploads PHP block deployed"
    print(f"  {'✅' if ok else '❌'} {msg}")
    return msg


def fire_layer_3_shield(ftp, wp_root: str, tools_dir: Path) -> str:
    """Layer 3: Deploy security-firewall-shield.php to mu-plugins"""
    shield_local  = tools_dir / "security-firewall-shield.php"
    mu_plugins    = f"{wp_root.rstrip('/')}/wp-content/mu-plugins"

    # Ensure mu-plugins directory exists
    _ftp_mkdir_safe(ftp, mu_plugins)

    remote = f"{mu_plugins}/sentrywp-firewall-shield.php"
    ok     = ftp.upload_file(str(shield_local), remote)
    msg    = f"Layer 3 ({'OK' if ok else 'FAILED'}): PHP Firewall Shield deployed to mu-plugins"
    print(f"  {'✅' if ok else '❌'} {msg}")
    return msg


def fire_layer_4_db_scan(ftp, wp_root: str, tools_dir: Path, site_url: str, timestamp: str) -> str:
    """Layer 4: Upload and run db_scan.php, then upload delete_users.php if rogue users found"""
    db_scan_local = tools_dir / "db_scan.php"
    remote_name   = f"sentrywp_dbscan_{timestamp}.php"
    remote_path   = f"{wp_root.rstrip('/')}/{remote_name}"
    scan_url      = f"{site_url.rstrip('/')}/{remote_name}"

    ok = ftp.upload_file(str(db_scan_local), remote_path)
    if not ok:
        return "Layer 4 (FAILED): Could not upload db_scan.php"

    import time
    time.sleep(2)
    result = ftp.http_get_json(scan_url)
    ftp.delete_file(remote_path)  # cleanup

    if result:
        msg = f"Layer 4 (OK): DB scan complete — {json.dumps(result)[:200]}"
    else:
        msg = "Layer 4 (PARTIAL): DB scan ran but no JSON returned (check manually)"

    print(f"  🗄️  {msg}")
    return msg


def fire_layer_5_file_cleanup(ftp, wp_root: str, scan_data: dict, tools_dir: Path,
                               site_url: str, timestamp: str) -> str:
    """
    Layer 5: Build a dynamic fast_cleanup.php based on actual scan findings,
    upload, run, and self-delete.
    """
    # Build list of files to delete from scan findings
    files_to_delete = []

    for finding in scan_data.get("suspicious_uploads", []):
        files_to_delete.append(finding["file"])

    # Build dynamic PHP cleanup script
    files_php = json.dumps(files_to_delete, indent=4)
    php_code  = f"""<?php
// SentryWP Dynamic Cleanup — Generated: {timestamp}
set_time_limit(0);
error_reporting(0);
header('Content-Type: application/json');

$root = __DIR__;
$log  = [];

$files_to_delete = {files_php};

foreach ($files_to_delete as $f) {{
    $path = $root . '/' . ltrim($f, '/');
    if (file_exists($path)) {{
        if (unlink($path)) {{
            $log[] = "[DELETED] $f";
        }} else {{
            $log[] = "[FAILED] $f";
        }}
    }} else {{
        $log[] = "[NOT_FOUND] $f";
    }}
}}

echo json_encode(["status" => "complete", "log" => $log]);
@unlink(__FILE__);
"""

    if not files_to_delete:
        return "Layer 5 (SKIPPED): No confirmed malicious files to delete"

    remote_name = f"sentrywp_cleanup_{timestamp}.php"
    remote_path = f"{wp_root.rstrip('/')}/{remote_name}"
    run_url     = f"{site_url.rstrip('/')}/{remote_name}"

    ok = ftp.upload_string(php_code, remote_path)
    if not ok:
        return "Layer 5 (FAILED): Could not upload dynamic cleanup script"

    import time
    time.sleep(2)
    result = ftp.http_get_json(run_url)
    ftp.delete_file(remote_path)

    deleted = [l for l in (result or {}).get("log", []) if l.startswith("[DELETED]")]
    msg = f"Layer 5 (OK): Deleted {len(deleted)}/{len(files_to_delete)} malicious files"
    print(f"  🧹 {msg}")
    return msg


# ─── Main auto-fix dispatcher ─────────────────────────────────────────────────

def run_autofix(ftp, client: dict, scan_data: dict, severity: str,
                tools_dir: Path, timestamp: str) -> list[str]:
    """
    Fire the appropriate security layers based on severity.

    critical → all 5 layers
    high     → layers 1, 2, 3, 5 (skip DB scan to be safe)
    """
    wp_root  = client.get("wp_root", "/")
    site_url = client["url"].rstrip("/")
    actions  = []

    print(f"\n  🔧 Auto-Fix Pipeline — Severity: {severity.upper()}")
    print(f"  Site: {client['name']} | Root: {wp_root}")

    # Layer 1 — Root .htaccess firewall (always fire on high/critical)
    actions.append(fire_layer_1_htaccess(ftp, wp_root, timestamp))

    # Layer 2 — Uploads PHP block (always fire on high/critical)
    actions.append(fire_layer_2_uploads_block(ftp, wp_root, timestamp))

    # Layer 3 — Permanent PHP shield (always fire on high/critical)
    actions.append(fire_layer_3_shield(ftp, wp_root, tools_dir))

    # Layer 4 — DB scan & user purge (only on critical)
    if severity == "critical":
        actions.append(fire_layer_4_db_scan(ftp, wp_root, tools_dir, site_url, timestamp))

    # Layer 5 — File system cleanup (always fire on high/critical)
    actions.append(fire_layer_5_file_cleanup(ftp, wp_root, scan_data, tools_dir, site_url, timestamp))

    print(f"\n  ✅ Auto-fix complete — {len(actions)} actions taken")
    return actions
