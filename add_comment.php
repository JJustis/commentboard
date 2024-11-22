<?php
// add_comment.php
// add_comment.php
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
    $title = $_POST['title'];
    $content = $_POST['content'];
    $should_encrypt = isset($_POST['encrypt']);
    
    if ($should_encrypt) {
        $content = encrypt($content, ENCRYPTION_KEY);
    }
    
    $conn->begin_transaction();
    
    try {
        // Insert comment
        $stmt = $conn->prepare("INSERT INTO comments (user_id, title, content, is_encrypted) 
                               VALUES (?, ?, ?, ?)");
        $stmt->bind_param("issi", $user_id, $title, $content, $should_encrypt);
        
        if (!$stmt->execute()) {
            throw new Exception("Error posting comment");
        }
        
        $comment_id = $conn->insert_id;
        
        // Handle image uploads
        if (isset($_FILES['images'])) {
            $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
            $max_size = 5 * 1024 * 1024; // 5MB per image
            $max_files = 5;
            
            $images = $_FILES['images'];
            $image_count = 0;
            
            for ($i = 0; $i < count($images['name']) && $image_count < $max_files; $i++) {
                if ($images['error'][$i] === 0 && 
                    in_array($images['type'][$i], $allowed_types) && 
                    $images['size'][$i] <= $max_size) {
                    
                    $file_extension = strtolower(pathinfo($images['name'][$i], PATHINFO_EXTENSION));
                    $new_filename = uniqid() . '.' . $file_extension;
                    $target_file = 'uploads/comments/' . $new_filename;
                    
                    if (move_uploaded_file($images['tmp_name'][$i], $target_file)) {
                        $stmt = $conn->prepare("INSERT INTO comment_images (comment_id, image_url) VALUES (?, ?)");
                        $stmt->bind_param("is", $comment_id, $target_file);
                        if (!$stmt->execute()) {
                            throw new Exception("Error saving image");
                        }
                        $image_count++;
                    }
                }
            }
        }
        
        $conn->commit();
        header('Location: index.php?msg=comment_posted');
        exit();
        
    } catch (Exception $e) {
        $conn->rollback();
        header('Location: index.php?error=' . urlencode($e->getMessage()));
        exit();
    }
}

?>