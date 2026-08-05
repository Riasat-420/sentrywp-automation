<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once('./wp-load.php');
global $wpdb;

$report = [
    'admin_users' => [],
    'suspicious_options' => [],
    'suspicious_posts' => [],
    'suspicious_dropins' => [],
    'core_file_checks' => []
];

// 1. Check for Admin Users
$admins = get_users(array('role' => 'administrator'));
foreach ($admins as $admin) {
    $report['admin_users'][] = [
        'username' => $admin->user_login,
        'email' => $admin->user_email
    ];
}

// 2. Check wp_options for injected scripts or weird values
$options = $wpdb->get_results("SELECT option_name, option_value FROM $wpdb->options WHERE option_value LIKE '%<script%' OR option_value LIKE '%<iframe%' OR option_value LIKE '%base64_decode%' LIMIT 50");
foreach ($options as $opt) {
    if (strpos($opt->option_name, '_transient_') === 0) continue;
    $report['suspicious_options'][] = [
        'name' => $opt->option_name,
        'value_snippet' => substr(strip_tags($opt->option_value), 0, 100)
    ];
}

// 3. Check wp_posts for injected JavaScript
$posts = $wpdb->get_results("SELECT ID, post_title, post_content FROM $wpdb->posts WHERE post_content LIKE '%<script%' LIMIT 50");
foreach ($posts as $p) {
    $report['suspicious_posts'][] = [
        'id' => $p->ID,
        'title' => $p->post_title
    ];
}

// 4. Check Stealth Drop-ins
$dropins = ['advanced-cache.php', 'object-cache.php', 'sunrise.php', 'maintenance.php', 'db.php', 'wp.zip'];
foreach ($dropins as $d) {
    $path = WP_CONTENT_DIR . '/' . $d;
    if (file_exists($path)) {
        $report['suspicious_dropins'][] = [
            'file' => $d,
            'size' => filesize($path)
        ];
    }
}

echo json_encode($report, JSON_PRETTY_PRINT);
@unlink(__FILE__);
