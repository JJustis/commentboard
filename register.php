<?php
// register.php
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $signature = $_POST['signature'] ?? '';
    $avatar_url = null;
    
    // Handle avatar upload
    if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] == 0) {
        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
        $max_size = 5 * 1024 * 1024; // 5MB
        
        if (in_array($_FILES['avatar']['type'], $allowed_types) && $_FILES['avatar']['size'] <= $max_size) {
            $file_extension = strtolower(pathinfo($_FILES['avatar']['name'], PATHINFO_EXTENSION));
            $new_filename = uniqid() . '.' . $file_extension;
            $target_file = 'uploads/avatars/' . $new_filename;
            
            if (move_uploaded_file($_FILES['avatar']['tmp_name'], $target_file)) {
                $avatar_url = $target_file;
            }
        }
    }
    
    if (register_user($username, $password, $avatar_url, $signature)) {
        // Auto-login after registration
        login_user($username, $password);
        header('Location: index.php?msg=registration_successful');
        exit();
    } else {
        header('Location: index.php?error=registration_failed');
        exit();
    }
}