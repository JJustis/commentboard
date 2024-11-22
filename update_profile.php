<?php

// update_profile.php
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
    $avatar_url = null;
    $signature = $_POST['signature'] ?? '';
    
    // Handle avatar upload
    if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] == 0) {
        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
        $max_size = 5 * 1024 * 1024; // 5MB
        
        if (in_array($_FILES['avatar']['type'], $allowed_types) && $_FILES['avatar']['size'] <= $max_size) {
            $file_extension = strtolower(pathinfo($_FILES['avatar']['name'], PATHINFO_EXTENSION));
            $new_filename = uniqid() . '.' . $file_extension;
            $target_file = 'uploads/avatars/' . $new_filename;
            
            if (move_uploaded_file($_FILES['avatar']['tmp_name'], $target_file)) {
                // Delete old avatar if exists
                $stmt = $conn->prepare("SELECT avatar_url FROM user_profiles WHERE user_id = ?");
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($row = $result->fetch_assoc()) {
                    if ($row['avatar_url'] && file_exists($row['avatar_url'])) {
                        unlink($row['avatar_url']);
                    }
                }
                $avatar_url = $target_file;
            }
        }
    }
    
    // Update profile
    $stmt = $conn->prepare("INSERT INTO user_profiles (user_id, avatar_url, signature) 
                           VALUES (?, ?, ?) 
                           ON DUPLICATE KEY UPDATE 
                           avatar_url = COALESCE(?, avatar_url),
                           signature = ?");
    $stmt->bind_param("issss", $user_id, $avatar_url, $signature, $avatar_url, $signature);
    
    if ($stmt->execute()) {
        header('Location: index.php?msg=profile_updated');
        exit();
    } else {
        header('Location: index.php?error=profile_update_failed');
        exit();
    }
}
