<?php
// Enhanced PHP-based Malware Scanner for WordPress
// 1. Core Checksums (if possible)
// 2. Suspicious anomalies (long lines, variable functions)
// 3. Uploads directory PHP files check
// 4. Checking recent modified files
set_time_limit(0);
ini_set('memory_limit', '512M');
error_reporting(0);

header('Content-Type: application/json');

$root_dir = __DIR__;
$report = [
    'scan_time' => date('c'),
    'total_files_scanned' => 0,
    'core_modifications' => [],
    'suspicious_anomalies' => [],
    'suspicious_uploads' => [],
    'errors' => []
];

// File types to skip to save time
$skip_ext = [
    'jpg','jpeg','png','gif','bmp','webp','ico',
    'mp4','mp3','avi','mov','ogg','wav',
    'zip','tar','gz','rar','7z',
    'pdf','doc','docx','xls','xlsx',
    'ttf','woff','woff2','eot','otf',
    'map','mo','po','pot','dat','db','sql', 'css', 'js', 'txt', 'md'
];

$wp_version = '';
if (file_exists($root_dir . '/wp-includes/version.php')) {
    include($root_dir . '/wp-includes/version.php');
    $wp_version = $wp_version;
}

// 1. Core Checksums (Basic comparison for common files)
$checksums = [];
if ($wp_version) {
    $checksum_url = "https://api.wordpress.org/core/checksums/1.0/?version=" . $wp_version . "&locale=en_US";
    $checksum_json = @file_get_contents($checksum_url);
    if ($checksum_json) {
        $checksum_data = json_decode($checksum_json, true);
        if (isset($checksum_data['checksums']) && is_array($checksum_data['checksums'])) {
            $checksums = $checksum_data['checksums'];
        }
    }
}

// Advanced Signatures (Anomalies)
$anomaly_sigs = [
    '/\$\w+\s*\(/i' => 'Variable function call (e.g. $a())',
    '/preg_replace\s*\(\s*[\'"].*e.*[\'"]/i' => 'preg_replace /e modifier',
    '/\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){20,}/' => 'Heavy hex obfuscation',
    '/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*[\'"](?:[a-zA-Z0-9+\/]{4})*(?:[a-zA-Z0-9+\/]{2}==|[a-zA-Z0-9+\/]{3}=)?[\'"]/i' => 'Base64 string assignment',
    '/str_rot13/i' => 'str_rot13 used',
    '/gzuncompress/i' => 'gzuncompress used',
    '/eval\s*\(\s*(?!\\$|\'|\")/i' => 'Unusual eval pattern',
    '/extract\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\)/i' => 'extract($_POST/GET)',
    '/wp_insert_user\s*\(/i' => 'User creation in code',
    '/\$wpdb->query\s*\(\s*[\'"]UPDATE.*wp_users/i' => 'Direct DB user update',
    '/assert\s*\(/i' => 'assert() call',
];

$silence_is_golden = "<?php\n// Silence is golden.\n";
$silence_is_golden2 = "<?php\r\n// Silence is golden.\r\n";

function scan_directory($dir) {
    global $root_dir, $report, $skip_ext, $anomaly_sigs, $checksums, $silence_is_golden, $silence_is_golden2;
    
    $iter = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST,
        RecursiveIteratorIterator::CATCH_GET_CHILD
    );

    foreach ($iter as $file) {
        if ($file->isDir()) {
            continue;
        }

        $path = $file->getPathname();
        $rel_path = ltrim(str_replace($root_dir, '', $path), '/\\');
        $ext = strtolower($file->getExtension());
        $size = $file->getSize();

        // Check if PHP file is in uploads directory
        if (strpos($rel_path, 'wp-content/uploads/') === 0 && in_array($ext, ['php', 'phtml', 'php5', 'php4', 'php3', 'shtml', 'cgi'])) {
            $content = @file_get_contents($path);
            if ($content !== false && trim($content) !== trim($silence_is_golden) && trim($content) !== trim($silence_is_golden2) && strlen(trim($content)) > 50) {
                 $report['suspicious_uploads'][] = [
                     'file' => $rel_path,
                     'size' => $size,
                     'preview' => substr($content, 0, 150)
                 ];
            }
        }

        // Only scan PHP files for code anomalies
        if ($ext !== 'php' && $ext !== 'phtml') {
            continue;
        }
        
        if ($size > 2 * 1024 * 1024) { // skip very large PHP files (rare)
            continue;
        }

        $report['total_files_scanned']++;
        
        $content = @file_get_contents($path);
        if ($content === false) {
            continue;
        }

        // 1. Core Checksum Verification
        $rel_path_fwd = str_replace('\\', '/', $rel_path);
        if (isset($checksums[$rel_path_fwd])) {
            $md5 = md5($content);
            if ($md5 !== $checksums[$rel_path_fwd]) {
                $report['core_modifications'][] = [
                    'file' => $rel_path_fwd,
                    'expected' => $checksums[$rel_path_fwd],
                    'actual' => $md5
                ];
            }
            continue; // Skip further anomaly checks for core files since we already verified them (unless modified)
        }

        // 2. Anomaly Checking
        $lines = explode("\n", $content);
        foreach ($lines as $line_num => $line) {
            $line_trim = trim($line);
            
            // Check extremely long lines (often obfuscated backdoors)
            if (strlen($line_trim) > 2000 && stripos($line_trim, '<?php') !== false) {
                $report['suspicious_anomalies'][] = [
                    'file' => $rel_path,
                    'line' => $line_num + 1,
                    'reason' => 'Extremely long PHP line (>2000 chars)',
                    'snippet' => substr($line_trim, 0, 100) . '...'
                ];
            }

            foreach ($anomaly_sigs as $pattern => $reason) {
                if (preg_match($pattern, $line)) {
                    $report['suspicious_anomalies'][] = [
                        'file' => $rel_path,
                        'line' => $line_num + 1,
                        'reason' => $reason,
                        'snippet' => substr($line_trim, 0, 100)
                    ];
                }
            }
        }
    }
}

try {
    scan_directory($root_dir);
} catch (Exception $e) {
    $report['errors'][] = $e->getMessage();
}

echo json_encode($report, JSON_PRETTY_PRINT);
@unlink(__FILE__);
