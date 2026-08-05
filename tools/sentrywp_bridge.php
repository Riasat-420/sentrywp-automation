<?php
/**
 * SentryWP Bridge — Permanent Authenticated Security Endpoint
 * ============================================================
 * Upload this file ONCE to your WordPress root via Hostinger File Manager.
 * GitHub Actions calls it via HTTPS POST — no FTP needed.
 *
 * SECRET: Change BRIDGE_SECRET below to match your SENTRYWP_BRIDGE_SECRET GitHub Secret.
 */

define('BRIDGE_SECRET', 'SWP-Br1dge-S3cr3t-K3y-2026');  // ← CHANGE THIS, must match GitHub Secret

// ─── Authentication ───────────────────────────────────────────────────────────
$provided_token = $_POST['token'] ?? $_SERVER['HTTP_X_SENTRYWP_TOKEN'] ?? '';

if (empty($provided_token) || !hash_equals(BRIDGE_SECRET, $provided_token)) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized — invalid token']);
    exit;
}

// ─── Setup ────────────────────────────────────────────────────────────────────
set_time_limit(120);
ini_set('memory_limit', '512M');
error_reporting(0);
header('Content-Type: application/json');

$root     = __DIR__;
$action   = $_POST['action'] ?? 'ping';

// ─── Router ──────────────────────────────────────────────────────────────────
switch ($action) {

    // ── PING: verify bridge is alive ──────────────────────────────────────────
    case 'ping':
        echo json_encode([
            'status'   => 'ok',
            'wp_root'  => $root,
            'php_ver'  => PHP_VERSION,
            'time'     => date('c'),
        ]);
        break;

    // ── SCAN: full malware scan (Layer 5) ─────────────────────────────────────
    case 'scan':
        echo json_encode(sentrywp_scan($root));
        break;

    // ── HARDEN: write security .htaccess files (Layers 1 & 2) ────────────────
    case 'harden':
        echo json_encode(sentrywp_harden($root));
        break;

    // ── SHIELD: deploy firewall to mu-plugins (Layer 3) ──────────────────────
    case 'shield':
        $shield_content = $_POST['shield_content'] ?? '';
        echo json_encode(sentrywp_deploy_shield($root, $shield_content));
        break;

    // ── CLEANUP: delete confirmed malicious files (Layer 5) ───────────────────
    case 'cleanup':
        $files = json_decode($_POST['files'] ?? '[]', true);
        echo json_encode(sentrywp_cleanup($root, $files));
        break;

    default:
        echo json_encode(['error' => 'Unknown action: ' . htmlspecialchars($action)]);
}


// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 5 — Full Malware Scanner
// ═══════════════════════════════════════════════════════════════════════════════

function sentrywp_scan($root_dir) {
    $report = [
        'scan_time'            => date('c'),
        'total_files_scanned'  => 0,
        'core_modifications'   => [],
        'suspicious_anomalies' => [],
        'suspicious_uploads'   => [],
        'errors'               => [],
    ];

    $skip_ext = [
        'jpg','jpeg','png','gif','bmp','webp','ico','svg',
        'mp4','mp3','avi','mov','ogg','wav',
        'zip','tar','gz','rar','7z',
        'pdf','doc','docx','xls','xlsx',
        'ttf','woff','woff2','eot','otf',
        'map','mo','po','pot','dat','db','sql','css','js','txt','md','xml','json',
    ];

    $anomaly_sigs = [
        '/\$\w+\s*\(/i'                        => 'Variable function call',
        '/preg_replace\s*\(\s*[\'"].*e.*[\'"]/i' => 'preg_replace /e modifier',
        '/\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){20,}/' => 'Heavy hex obfuscation',
        '/eval\s*\(\s*base64_decode/i'          => 'eval+base64_decode',
        '/str_rot13/i'                           => 'str_rot13 used',
        '/gzuncompress/i'                        => 'gzuncompress used',
        '/assert\s*\(/i'                         => 'assert() call',
        '/extract\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\)/i' => 'extract($_POST/GET)',
        '/wp_insert_user\s*\(/i'                => 'User creation in code',
        '/\$wpdb->query\s*\(\s*[\'"]UPDATE.*wp_users/i' => 'Direct DB user update',
    ];

    // Get WP version for core checksums
    $checksums    = [];
    $wp_version   = '';
    $ver_file     = $root_dir . '/wp-includes/version.php';
    if (file_exists($ver_file)) {
        $ver_content = file_get_contents($ver_file);
        if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $ver_content, $m)) {
            $wp_version = $m[1];
        }
    }
    if ($wp_version) {
        $checksum_url  = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale=en_US";
        $checksum_json = @file_get_contents($checksum_url);
        if ($checksum_json) {
            $data = json_decode($checksum_json, true);
            if (!empty($data['checksums'])) {
                $checksums = $data['checksums'];
            }
        }
    }

    $iter = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root_dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST,
        RecursiveIteratorIterator::CATCH_GET_CHILD
    );

    foreach ($iter as $file) {
        if ($file->isDir()) continue;

        $path     = $file->getPathname();
        $rel      = ltrim(str_replace($root_dir, '', $path), '/\\');
        $ext      = strtolower($file->getExtension());
        $size     = $file->getSize();

        // Check PHP in uploads
        if (strpos($rel, 'wp-content/uploads/') === 0 &&
            in_array($ext, ['php','phtml','php5','php4','php3','shtml','cgi'])) {
            $content = @file_get_contents($path);
            if ($content !== false && strlen(trim($content)) > 50) {
                $report['suspicious_uploads'][] = [
                    'file'    => $rel,
                    'size'    => $size,
                    'preview' => substr($content, 0, 150),
                ];
            }
        }

        if (!in_array($ext, ['php','phtml'])) continue;
        if ($size > 2 * 1024 * 1024)          continue;
        if (basename($path) === basename(__FILE__)) continue; // skip self

        $report['total_files_scanned']++;
        $content = @file_get_contents($path);
        if ($content === false) continue;

        // Core checksum verification
        $rel_fwd = str_replace('\\', '/', $rel);
        if (isset($checksums[$rel_fwd])) {
            if (md5($content) !== $checksums[$rel_fwd]) {
                $report['core_modifications'][] = [
                    'file'     => $rel_fwd,
                    'expected' => $checksums[$rel_fwd],
                    'actual'   => md5($content),
                ];
            }
            continue;
        }

        // Anomaly scan
        $lines = explode("\n", $content);
        foreach ($lines as $line_num => $line) {
            $line_trim = trim($line);
            if (strlen($line_trim) > 2000 && stripos($line_trim, '<?php') !== false) {
                $report['suspicious_anomalies'][] = [
                    'file'    => $rel,
                    'line'    => $line_num + 1,
                    'reason'  => 'Extremely long PHP line (>2000 chars)',
                    'snippet' => substr($line_trim, 0, 100) . '...',
                ];
            }
            foreach ($anomaly_sigs as $pattern => $reason) {
                if (preg_match($pattern, $line)) {
                    $report['suspicious_anomalies'][] = [
                        'file'    => $rel,
                        'line'    => $line_num + 1,
                        'reason'  => $reason,
                        'snippet' => substr($line_trim, 0, 100),
                    ];
                }
            }
        }
    }

    return $report;
}


// ═══════════════════════════════════════════════════════════════════════════════
// LAYERS 1 & 2 — .htaccess Hardening
// ═══════════════════════════════════════════════════════════════════════════════

function sentrywp_harden($root_dir) {
    $ts  = date('Y-m-d H:i:s') . ' UTC';
    $log = [];

    // Layer 1: Root .htaccess
    $root_htaccess = <<<HTACCESS
# BEGIN SentryWP Security Hardening — {$ts}
Options -Indexes
<Files wp-config.php>
    Require all denied
</Files>
<Files xmlrpc.php>
    Require all denied
</Files>
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
HTACCESS;

    $path1 = $root_dir . '/.htaccess';
    if (file_put_contents($path1, $root_htaccess) !== false) {
        $log[] = 'Layer 1 (OK): Root .htaccess firewall written';
    } else {
        $log[] = 'Layer 1 (FAILED): Could not write root .htaccess';
    }

    // Layer 2: Uploads PHP block
    $uploads_htaccess = <<<HTACCESS2
# SentryWP: Block PHP execution in uploads — {$ts}
<FilesMatch "\.(php|php4|php5|php7|php8|phtml|phar|pht|sh|cgi|pl)$">
    Require all denied
</FilesMatch>
<IfModule mod_php8.c>
    php_flag engine off
</IfModule>
HTACCESS2;

    $uploads_dir = $root_dir . '/wp-content/uploads';
    if (is_dir($uploads_dir)) {
        $path2 = $uploads_dir . '/.htaccess';
        if (file_put_contents($path2, $uploads_htaccess) !== false) {
            $log[] = 'Layer 2 (OK): Uploads PHP block deployed';
        } else {
            $log[] = 'Layer 2 (FAILED): Could not write uploads .htaccess';
        }
    } else {
        $log[] = 'Layer 2 (SKIPPED): uploads dir not found';
    }

    return ['status' => 'complete', 'log' => $log];
}


// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 3 — PHP Firewall Shield (mu-plugins)
// ═══════════════════════════════════════════════════════════════════════════════

function sentrywp_deploy_shield($root_dir, $shield_content) {
    $mu_dir = $root_dir . '/wp-content/mu-plugins';
    if (!is_dir($mu_dir)) {
        @mkdir($mu_dir, 0755, true);
    }
    $target = $mu_dir . '/sentrywp-firewall-shield.php';
    if (file_put_contents($target, $shield_content) !== false) {
        return ['status' => 'ok', 'message' => 'Layer 3: Firewall shield deployed to mu-plugins'];
    }
    return ['status' => 'error', 'message' => 'Layer 3: Could not write firewall shield'];
}


// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 5 — File Cleanup
// ═══════════════════════════════════════════════════════════════════════════════

function sentrywp_cleanup($root_dir, $files) {
    $log     = [];
    $deleted = 0;
    foreach ($files as $rel_path) {
        $path = $root_dir . '/' . ltrim(str_replace('..', '', $rel_path), '/');
        if (file_exists($path)) {
            if (@unlink($path)) {
                $log[] = "[DELETED] {$rel_path}";
                $deleted++;
            } else {
                $log[] = "[FAILED] {$rel_path}";
            }
        } else {
            $log[] = "[NOT_FOUND] {$rel_path}";
        }
    }
    return [
        'status'  => 'complete',
        'deleted' => $deleted,
        'total'   => count($files),
        'log'     => $log,
    ];
}
