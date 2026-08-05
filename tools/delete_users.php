<?php
require_once('./wp-load.php');
require_once(ABSPATH . 'wp-admin/includes/user.php');

$users_to_delete = ['admin', 'backupadmin', 'wp-backup'];
$deleted = 0;

foreach ($users_to_delete as $username) {
    $user = get_user_by('login', $username);
    if ($user) {
        // Reassign any posts they might have created to the legit admin (lefeywev)
        $legit_admin = get_user_by('login', 'lefeywev');
        $reassign_to = $legit_admin ? $legit_admin->ID : null;
        
        if (wp_delete_user($user->ID, $reassign_to)) {
            echo "[+] Deleted malicious user: $username\n";
            $deleted++;
        } else {
            echo "[-] Failed to delete user: $username\n";
        }
    }
}

if ($deleted == 0) {
    echo "No malicious users found to delete.\n";
} else {
    echo "Successfully deleted $deleted malicious users!\n";
}
@unlink(__FILE__);
