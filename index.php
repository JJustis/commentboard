
<?php
// Add this function at the top of index.php after the existing functions

function purify_html($html) {
    // List of allowed tags and attributes
    $allowed_tags = [
        'p' => ['class', 'style'],
        'b' => [],
        'strong' => [],
        'i' => [],
        'em' => [],
        'u' => [],
        'a' => ['href', 'title', 'target'],
        'ul' => ['class'],
        'ol' => ['class'],
        'li' => [],
        'br' => [],
        'hr' => [],
        'span' => ['class', 'style'],
        'div' => ['class', 'style'],
        'h1' => ['class'],
        'h2' => ['class'],
        'h3' => ['class'],
        'h4' => ['class'],
        'h5' => ['class'],
        'h6' => ['class'],
        'code' => ['class'],
        'pre' => ['class']
    ];
    
    // Load HTML content
    $dom = new DOMDocument();
    libxml_use_internal_errors(true); // Suppress HTML5 tag warnings
    $dom->loadHTML(mb_convert_encoding($html, 'HTML-ENTITIES', 'UTF-8'), LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
    libxml_clear_errors();
    
    // Function to clean nodes recursively
    function clean_node($node, $allowed_tags) {
        if ($node->nodeType === XML_ELEMENT_NODE) {
            // Check if the tag is allowed
            if (!isset($allowed_tags[strtolower($node->tagName)])) {
                // Replace forbidden tag with its content
                while ($node->hasChildNodes()) {
                    $node->parentNode->insertBefore($node->firstChild, $node);
                }
                $node->parentNode->removeChild($node);
                return;
            }
            
            // Clean attributes
            $allowed_attributes = $allowed_tags[strtolower($node->tagName)];
            $attributes = [];
            foreach ($node->attributes as $attribute) {
                $attributes[] = $attribute->name;
            }
            foreach ($attributes as $attribute) {
                if (!in_array($attribute, $allowed_attributes)) {
                    $node->removeAttribute($attribute);
                }
            }
            
            // Clean href attributes to prevent javascript:
            if ($node->hasAttribute('href')) {
                $href = $node->getAttribute('href');
                if (preg_match('/^(?:javascript|data|vbscript):/i', $href)) {
                    $node->removeAttribute('href');
                }
            }
        }
        
        // Clean child nodes
        $children = [];
        foreach ($node->childNodes as $child) {
            $children[] = $child;
        }
        foreach ($children as $child) {
            clean_node($child, $allowed_tags);
        }
    }
    
    // Clean the document
    clean_node($dom->documentElement, $allowed_tags);
    
    // Return cleaned HTML
    return $dom->saveHTML();
}

// Modify the comment display section in index.php
// Replace the existing content echo line:
// From: echo nl2br(htmlspecialchars($content));
// To:

// config.php - Save this as a separate file
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');     // Default XAMPP username
define('DB_PASSWORD', '');         // Default XAMPP password
define('DB_NAME', 'comments_db');
define('ENCRYPTION_KEY', 'uhf43hq94yhwh2ouuhy4u2093ur');

// Create connection
$conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Create database if it doesn't exist
$sql = "CREATE DATABASE IF NOT EXISTS " . DB_NAME;
if (!$conn->query($sql)) {
    die("Error creating database: " . $conn->error);
}

// Select the database
$conn->select_db(DB_NAME);

// Create users table
$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";
if (!$conn->query($sql)) {
    die("Error creating users table: " . $conn->error);
}

// Create user_profiles table
$sql = "CREATE TABLE IF NOT EXISTS user_profiles (
    user_id INT PRIMARY KEY,
    avatar_url VARCHAR(255),
    signature TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)";
if (!$conn->query($sql)) {
    die("Error creating user_profiles table: " . $conn->error);
}

// Create comments table
$sql = "CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    title VARCHAR(255) NOT NULL,
    content TEXT,
    is_encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)";
if (!$conn->query($sql)) {
    die("Error creating comments table: " . $conn->error);
}

// Create comment_images table
$sql = "CREATE TABLE IF NOT EXISTS comment_images (
    id INT AUTO_INCREMENT PRIMARY KEY,
    comment_id INT,
    image_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (comment_id) REFERENCES comments(id) ON DELETE CASCADE
)";
if (!$conn->query($sql)) {
    die("Error creating comment_images table: " . $conn->error);
}

// Create required directories
$directories = [
    'uploads',
    'uploads/avatars',
    'uploads/comments'
];

foreach ($directories as $dir) {
    if (!file_exists($dir)) {
        mkdir($dir, 0777, true);
    }
}

// Encryption functions
function encrypt($data, $key) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    return base64_encode($encrypted . '::' . $iv);
}

function decrypt($data, $key) {
    list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
}

// User functions
function register_user($username, $password, $avatar = null, $signature = null) {
    global $conn;
    
    $password_hash = password_hash($password, PASSWORD_DEFAULT);
    
    // Start transaction
    $conn->begin_transaction();
    
    try {
        // Insert user
        $stmt = $conn->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
        $stmt->bind_param("ss", $username, $password_hash);
        
        if (!$stmt->execute()) {
            throw new Exception("Error creating user: " . $conn->error);
        }
        
        $user_id = $conn->insert_id;
        
        // Insert profile
        $stmt = $conn->prepare("INSERT INTO user_profiles (user_id, avatar_url, signature) VALUES (?, ?, ?)");
        $stmt->bind_param("iss", $user_id, $avatar, $signature);
        
        if (!$stmt->execute()) {
            throw new Exception("Error creating user profile: " . $conn->error);
        }
        
        // Commit transaction
        $conn->commit();
        return true;
        
    } catch (Exception $e) {
        // Rollback transaction on error
        $conn->rollback();
        error_log($e->getMessage());
        return false;
    }
}

function login_user($username, $password) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT id, password_hash FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($row = $result->fetch_assoc()) {
        if (password_verify($password, $row['password_hash'])) {
            $_SESSION['user_id'] = $row['id'];
            return true;
        }
    }
    return false;
}

// Initialize session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Comment System</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
	    .card-text {
        overflow-wrap: break-word;
        word-wrap: break-word;
    }
    .card-text pre {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 4px;
        overflow-x: auto;
    }
    .card-text code {
        background: #f8f9fa;
        padding: 0.2rem 0.4rem;
        border-radius: 3px;
    }
        .comment-card {
            transition: transform 0.2s;
        }
        .comment-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .avatar {
            width: 64px;
            height: 64px;
            object-fit: cover;
            border-radius: 50%;
        }
        .signature {
            border-top: 1px solid #eee;
            font-style: italic;
            color: #666;
            margin-top: 10px;
            padding-top: 10px;
        }
        .gallery-img {
            height: 150px;
            object-fit: cover;
            cursor: pointer;
        }
        .search-box {
            background: rgba(255,255,255,0.9);
            backdrop-filter: blur(10px);
            border: 1px solid #eee;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
		
    </style>
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-comments me-2"></i>
                Comment Board
            </a>
            <?php if (isset($_SESSION['user_id'])): ?>
            <div class="ms-auto">
                <a href="#" class="btn btn-light" data-bs-toggle="modal" data-bs-target="#profileModal">
                    <i class="fas fa-user me-2"></i>Profile
                </a>
                <a href="logout.php" class="btn btn-outline-light ms-2">
                    <i class="fas fa-sign-out-alt me-2"></i>Logout
                </a>
            </div>
            <?php endif; ?>
        </div>
    </nav>

    <div class="container">
        <?php if (!isset($_SESSION['user_id'])): ?>
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card shadow-sm">
                    <div class="card-body">
                        <ul class="nav nav-tabs" role="tablist">
                            <li class="nav-item">
                                <a class="nav-link active" data-bs-toggle="tab" href="#login">Login</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" data-bs-toggle="tab" href="#register">Register</a>
                            </li>
                        </ul>
                        
                        <div class="tab-content pt-4">
                            <div id="login" class="tab-pane active">
                                <form method="post" action="login.php">
                                    <div class="mb-3">
                                        <input type="text" name="username" class="form-control" placeholder="Username" required>
                                    </div>
                                    <div class="mb-3">
                                        <input type="password" name="password" class="form-control" placeholder="Password" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="fas fa-sign-in-alt me-2"></i>Login
                                    </button>
                                </form>
                            </div>
                            
                            <div id="register" class="tab-pane fade">
                                <form method="post" action="register.php" enctype="multipart/form-data">
                                    <div class="mb-3">
                                        <input type="text" name="username" class="form-control" placeholder="Username" required>
                                    </div>
                                    <div class="mb-3">
                                        <input type="password" name="password" class="form-control" placeholder="Password" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Avatar</label>
                                        <input type="file" name="avatar" class="form-control" accept="image/*">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Signature</label>
                                        <textarea name="signature" class="form-control" rows="2"></textarea>
                                    </div>
                                    <button type="submit" class="btn btn-success w-100">
                                        <i class="fas fa-user-plus me-2"></i>Register
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php else: ?>
        <!-- Search Bar -->
        <div class="search-box sticky-top py-3">
            <div class="input-group">
                <span class="input-group-text bg-white">
                    <i class="fas fa-search"></i>
                </span>
                <input type="text" id="searchBox" class="form-control" placeholder="Search comments...">
            </div>
        </div>

        <!-- New Comment Form -->
        <div class="card shadow-sm mb-4">
            <div class="card-body">
                <h5 class="card-title">
                    <i class="fas fa-pen me-2"></i>New Comment
                </h5>
                <form method="post" action="add_comment.php" enctype="multipart/form-data">
                    <div class="mb-3">
                        <input type="text" name="title" class="form-control" placeholder="Title" required>
                    </div>
                    <div class="mb-3">
                        <textarea name="content" class="form-control" rows="3" placeholder="Content" required></textarea>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Images (Max 5)</label>
                        <input type="file" name="images[]" class="form-control" accept="image/*" multiple>
                    </div>
                    <div class="form-check mb-3">
                        <input type="checkbox" name="encrypt" id="encrypt" class="form-check-input">
                        <label class="form-check-label" for="encrypt">Encrypt this comment</label>
                    </div>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-paper-plane me-2"></i>Post Comment
                    </button>
                </form>
            </div>
        </div>

        <!-- Comments Display -->
        <div id="comments">
            <?php
            $sql = "SELECT c.*, u.username, up.avatar_url, up.signature, 
                    GROUP_CONCAT(ci.image_url) as images 
                    FROM comments c 
                    JOIN users u ON c.user_id = u.id 
                    LEFT JOIN user_profiles up ON u.id = up.user_id 
                    LEFT JOIN comment_images ci ON c.id = ci.comment_id 
                    GROUP BY c.id 
                    ORDER BY created_at DESC";
            $result = $conn->query($sql);

            if ($result === false) {
                echo "<div class='alert alert-danger'><i class='fas fa-exclamation-circle me-2'></i>Error fetching comments: " . $conn->error . "</div>";
            } else if ($result->num_rows == 0) {
                echo "<div class='alert alert-info'><i class='fas fa-info-circle me-2'></i>No comments yet.</div>";
            } else {
                while ($row = $result->fetch_assoc()) {
                    $content = $row['is_encrypted'] ? 
                              decrypt($row['content'], ENCRYPTION_KEY) : 
                              $row['content'];
                    ?>
                    <div class="card comment-card mb-4">
                        <div class="card-header d-flex align-items-center">
                            <img src="<?php echo $row['avatar_url'] ?? 'default-avatar.png'; ?>" 
                                 class="avatar me-3" alt="User Avatar">
                            <div>
                                <h5 class="mb-0"><?php echo htmlspecialchars($row['username']); ?></h5>
                                <small class="text-muted">
                                    <i class="fas fa-clock me-1"></i>
                                    <?php echo date('F j, Y, g:i a', strtotime($row['created_at'])); ?>
                                </small>
                            </div>
                            <?php if ($row['is_encrypted']): ?>
                                <span class="ms-auto badge bg-warning">
                                    <i class="fas fa-lock me-1"></i>Encrypted
                                </span>
                            <?php endif; ?>
                        </div>
                        <div class="card-body">
                            <h5 class="card-title"><?php echo htmlspecialchars($row['title']); ?></h5>
                            <p class="card-text">
    <?php 
    if ($row['is_encrypted']) {
        echo nl2br(htmlspecialchars($content));
    } else {
        echo purify_html($content);
    } 
    ?>
</p>
                            
                            <?php if ($row['images']): ?>
                            <div class="row g-2 mb-3">
                                <?php foreach(explode(',', $row['images']) as $image): ?>
                                <div class="col-md-4 col-lg-3">
                                    <img src="<?php echo htmlspecialchars($image); ?>" 
                                         class="img-fluid rounded gallery-img" 
                                         data-bs-toggle="modal" 
                                         data-bs-target="#imageModal">
                                </div>
                                <?php endforeach; ?>
                            </div>
                            <?php endif; ?>

                            <?php if ($row['signature']): ?>
                            <div class="signature">
                                <?php echo htmlspecialchars($row['signature']); ?>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?php
                }
            }
            ?>
        </div>
        <?php endif; ?>
    </div>

    <!-- Image Modal -->
    <div class="modal fade" id="imageModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-body p-0">
                    <img src="" class="img-fluid">
                </div>
            </div>
        </div>
    </div>

    <!-- Profile Modal -->
    <div class="modal fade" id="profileModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Edit Profile</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form method="post" action="update_profile.php" enctype="multipart/form-data">
                        <div class="mb-3">
                            <label class="form-label">Avatar</label>
                            <input type="file" name="avatar" class="form-control" accept="image/*">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Signature</label>
                            <textarea name="signature" class="form-control" rows="3"></textarea>
                        </div>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Search functionality
    document.getElementById('searchBox').addEventListener('keyup', function() {
        const searchText = this.value.toLowerCase();
        const comments = document.querySelectorAll('.comment-card');
        
        comments.forEach(comment => {
            const title = comment.querySelector('.card-title').textContent.toLowerCase();
            const content = comment.querySelector('.card-text').textContent.toLowerCase();
            
            if (title.includes(searchText) || content.includes(searchText)) {
                comment.style.display = '';
            } else {
                comment.style.display = 'none';
            }
        });
    });

    // Image modal
    document.querySelectorAll('.gallery-img').forEach(img => {
        img.addEventListener('click', function() {
            const modal = document.querySelector('#imageModal');
            const modalImg = modal.querySelector('img');
            modalImg.src = this.src;
        });
    });
    </script>
</body>
</html>