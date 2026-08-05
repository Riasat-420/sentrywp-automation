<?php
// Fast PHP-based Malware Cleanup Script
// Deletes specified malicious files and directories locally on the server.
set_time_limit(0);
error_reporting(0);

header('Content-Type: text/plain');

$root_dir = __DIR__;
$log = [];

$files_to_delete = [
    "wp-optimaized.php",
    "mwr.txt",
    "CDX1.php",
    "CDX2.php",
    "wp-Blogs.php",
    "wp-sx9.php",
    "wp-system.php",
    "kzahel3o.php",
    "l6tvneky.php",
    "default.php",
    ".private/320211/201597/737150/207985/41791/index.php",
    "wp-admin/network/461716/561835/543442/983841/index.php"
];

$dirs_to_delete = [
    "wp-content/plugins/kzahel3o",
    "wp-content/plugins/l6tvneky"
];

function delete_dir_recursive($dir) {
    global $log;
    if (!file_exists($dir)) {
        return true;
    }
    if (!is_dir($dir)) {
        return unlink($dir);
    }
    foreach (scandir($dir) as $item) {
        if ($item == '.' || $item == '..') {
            continue;
        }
        if (!delete_dir_recursive($dir . DIRECTORY_SEPARATOR . $item)) {
            $log[] = "Failed to delete: " . $dir . DIRECTORY_SEPARATOR . $item;
            return false;
        }
    }
    $res = rmdir($dir);
    if ($res) {
        $log[] = "[DELETED DIR] $dir";
    } else {
        $log[] = "[ERROR] Could not remove dir: $dir";
    }
    return $res;
}

echo "[*] Starting PHP Fast Cleanup...\n\n";

echo "[*] Deleting Files:\n";
foreach ($files_to_delete as $f) {
    $path = $root_dir . DIRECTORY_SEPARATOR . $f;
    if (file_exists($path)) {
        if (unlink($path)) {
            echo "  [DELETED] $f\n";
        } else {
            echo "  [ERROR] Failed to delete: $f\n";
        }
    } else {
        echo "  [SKIPPED] $f (Already deleted)\n";
    }
}

echo "\n[*] Deleting Directories:\n";
foreach ($dirs_to_delete as $d) {
    $path = $root_dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $d);
    if (file_exists($path)) {
        delete_dir_recursive($path);
        echo "  [DELETED DIR TREE] $d\n";
    } else {
        echo "  [SKIPPED] $d (Already deleted)\n";
    }
}

echo "\n[+] Cleanup Log for Directories:\n";
foreach ($log as $l) {
    echo $l . "\n";
}

echo "\n[+] FAST CLEANUP COMPLETE!\n";
@unlink(__FILE__); // self delete after running
