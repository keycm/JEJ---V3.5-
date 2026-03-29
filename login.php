<?php
// login.php
include 'config.php';

$error = "";
if(isset($_POST['login'])){
    $email = $_POST['email'];
    $p = md5($_POST['password']);

    $check = $conn->query("SELECT * FROM users WHERE email='$email' AND password='$p'");

    if($check->num_rows > 0){
        $row = $check->fetch_assoc();
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['fullname'] = $row['fullname'] ?? explode('@', $row['email'])[0];
        $_SESSION['role'] = $row['role'] ?? 'BUYER';
        
        header("Location: index.php"); 
        exit();
    } else {
        $error = "Invalid email or password.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In | EcoEstates</title>
    <link rel="stylesheet" href="assets/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body class="login-body">
    
    <div class="login-box">
        <div style="font-size: 40px; margin-bottom: 10px;">🌲</div>
        
        <h2>EcoEstates</h2>
        <span class="version">System v2.0</span>

        <?php if(isset($_GET['success'])): ?>
            <div style="background:#e8f5e9; color:#2e7d32; padding:10px; border-radius:6px; font-size:13px; margin-bottom:15px;">
                Registration successful! Please login.
            </div>
        <?php endif; ?>

        <?php if($error): ?>
            <div style="background:#ffebee; color:#c62828; padding:10px; border-radius:6px; font-size:13px; margin-bottom:15px;">
                <?= $error ?>
            </div>
        <?php endif; ?>

        <form method="POST">
            <div class="input-group">
                <i class="fa-solid fa-envelope"></i>
                <input type="email" name="email" placeholder="Email Address" required>
            </div>

            <div class="input-group">
                <i class="fa-solid fa-lock"></i>
                <input type="password" name="password" placeholder="Password" required>
            </div>

            <button type="submit" name="login" class="btn-login">
                LOGIN NOW
            </button>
        </form>

        <div class="small-text">
            Don't have an account? <a href="register.php">Register here</a><br><br>
            Go back to <a href="index.php">Website Homepage</a>
        </div>
    </div>

</body>
</html>