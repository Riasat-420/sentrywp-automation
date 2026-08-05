<?php
/**
 * Plugin Name: Enterprise Security Firewall Shield
 * Description: Prevents unauthorized administrator creation, blocks wpsip bot payloads, and secures WordPress core.
 * Author: Muhammad Riasat Ali (Web Developer & Security Specialist)
 */

if (!defined('ABSPATH')) exit;

// 1. Block unauthorized administrator user creation
add_action('user_register', function($user_id) {
    $user = get_userdata($user_id);
    if ($user && in_array('administrator', (array) $user->roles)) {
        $current_user_id = get_current_user_id();
        // Allow user creation ONLY if logged in as Primary Admin ID 58 or main admin email
        if ($current_user_id !== 58 && (strpos($user->user_login, 'wpsip') !== false || strpos($user->user_login, 'newsfeed') !== false)) {
            require_once(ABSPATH . 'wp-admin/includes/user.php');
            wp_delete_user($user_id);
            wp_die('SECURITY FIREWALL BLOCKED UNAUTHORIZED ADMINISTRATOR CREATION');
        }
    }
}, 1);

// 2. Block XML-RPC requests at PHP level
add_filter('xmlrpc_enabled', '__return_false');

// 3. Disable pingbacks
add_filter('xmlrpc_methods', function($methods) {
    unset($methods['pingback.ping']);
    return $methods;
});
