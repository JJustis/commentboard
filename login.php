<?php
// login.php
// login.php
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    if (login_user($username, $password)) {
        header('Location: index.php');
        exit();
    } else {
        header('Location: index.php?error=invalid_credentials');
        exit();
    }
}
?>