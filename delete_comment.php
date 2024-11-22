<?php
// delete_comment.php
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_SESSION['user_id'])) {
    $comment_id = $_POST['comment_id'];
    $user_id = $_SESSION['user_id'];
    
    // Verify user owns the comment
    $stmt = $conn->prepare("SELECT user_id FROM comments WHERE id = ?");
    $stmt->bind_param("i", $comment_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($row = $result->fetch_assoc()) {
        if ($row['user_id'] == $user_id) {
            $conn->begin_transaction();
            
            try {
                // Delete associated images first
                $stmt = $conn->prepare("SELECT image_url FROM comment_images WHERE comment_id = ?");
                $stmt->bind_param("i", $comment_id);
                $stmt->execute();
                $result = $stmt->get_result();
                
                while ($row = $result->fetch_assoc()) {
                    if (file_exists($row['image_url'])) {
                        unlink($row['image_url']);
                    }
                }
                
                // Delete comment (will cascade to comment_images)
                $stmt = $conn->prepare("DELETE FROM comments WHERE id = ?");
                $stmt->bind_param("i", $comment_id);
                $stmt->execute();
                
                $conn->commit();
                header('Location: index.php?msg=comment_deleted');
                exit();
                
            } catch (Exception $e) {
                $conn->rollback();
                header('Location: index.php?error=delete_failed');
                exit();
            }
        }
    }
}
header('Location: index.php?error=unauthorized');
exit();