<?php
// config.php
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '');
define('DB_NAME', 'comments_db');
define('ENCRYPTION_KEY', 'uhf43hq94yhwh2ouuhy4u2093ur'); // Store this securely in production
session_start();
// Initialize database
$conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Create database if it doesn't exist
$sql = "CREATE DATABASE IF NOT EXISTS " . DB_NAME;
if ($conn->query($sql) === FALSE) {
    die("Error creating database: " . $conn->error);
}

// Select the database
$conn->select_db(DB_NAME);

// Create users table if it doesn't exist
$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";

if ($conn->query($sql) === FALSE) {
    die("Error creating users table: " . $conn->error);
}

// Create comments table if it doesn't exist
$sql = "CREATE TABLE IF NOT EXISTS comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)";

if ($conn->query($sql) === FALSE) {
    die("Error creating comments table: " . $conn->error);
}

// Functions for encryption/decryption
function encrypt($data, $key) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    return base64_encode($encrypted . '::' . $iv);
}

function decrypt($data, $key) {
    list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
}

// Authentication functions
function register_user($username, $password) {
    global $conn;
    $password_hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $conn->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
    if ($stmt === FALSE) {
        return FALSE;
    }
    $stmt->bind_param("ss", $username, $password_hash);
    return $stmt->execute();
}

function login_user($username, $password) {
    global $conn;
    
    try {
        // Make sure we're connected to the correct database
        if (!$conn->ping()) {
            $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
        }
        
        // Prepare statement
        $stmt = $conn->prepare("SELECT id, username, password_hash FROM users WHERE username = ?");
        if ($stmt === false) {
            throw new Exception("Failed to prepare statement: " . $conn->error);
        }
        
        // Bind parameters
        if (!$stmt->bind_param("s", $username)) {
            throw new Exception("Failed to bind parameters: " . $stmt->error);
        }
        
        // Execute the query
        if (!$stmt->execute()) {
            throw new Exception("Failed to execute query: " . $stmt->error);
        }
        
        // Get the result
        $result = $stmt->get_result();
        if ($result === false) {
            throw new Exception("Failed to get result: " . $stmt->error);
        }
        
        if ($row = $result->fetch_assoc()) {
            if (password_verify($password, $row['password_hash'])) {
                // Start session if not already started
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }
                
                // Set session variables
                $_SESSION['user_id'] = $row['id'];
                $_SESSION['username'] = $row['username'];
                $_SESSION['logged_in'] = true;
                
                return true;
            }
        }
        
        return false;
        
    } catch (Exception $e) {
        error_log("Login error: " . $e->getMessage());
        return false;
    } finally {
        if (isset($stmt)) {
            $stmt->close();
        }
    }
}
?>