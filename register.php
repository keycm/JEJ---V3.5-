<?php
// register.php
include 'config.php';

// Include PHPMailer classes safely
if (file_exists('PHPMailer/Exception.php') && file_exists('PHPMailer/PHPMailer.php') && file_exists('PHPMailer/SMTP.php')) {
    require 'PHPMailer/Exception.php';
    require 'PHPMailer/PHPMailer.php';
    require 'PHPMailer/SMTP.php';
}

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$error = "";
$success_msg = "";

if (isset($_POST['register'])) {
    // Store raw data in session, escape only when inserting to DB
    $fullname = trim($_POST['fullname']);
    $phone = trim($_POST['phone']);
    $email = trim($_POST['email']);
    $password_raw = $_POST['password'];
    
    // Check if email already exists
    $escaped_email = $conn->real_escape_string($email);
    $check = $conn->query("SELECT * FROM users WHERE email='$escaped_email'");

    if ($check->num_rows > 0) {
        $error = "Email is already registered.";
    } else {
        // Generate a 6-digit OTP
        $otp = rand(100000, 999999);
        
        // Store user data in session
        $_SESSION['temp_user'] = [
            'fullname' => $fullname,
            'phone' => $phone,
            'email' => $email,
            'password' => md5($password_raw), // Store hashed password
            'otp' => $otp,
            'attempts' => 0
        ];
        
        // Send OTP via email using PHPMailer and Gmail SMTP
        if (class_exists('PHPMailer\PHPMailer\PHPMailer')) {
            $mail = new PHPMailer(true);
            try {
                // Server settings
                $mail->isSMTP();
                $mail->Host       = 'smtp.gmail.com'; 
                $mail->SMTPAuth   = true;
                
                // Updated Credentials
                $mail->Username   = 'publicotavern@gmail.com'; 
                $mail->Password   = 'xcvgrzzsjvnbtsti';   // App password without spaces
                
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // Enable TLS encryption
                $mail->Port       = 587;                            // TCP port to connect to

                // Bypass SSL certificate verification (Useful for local development XAMPP/WAMP)
                $mail->SMTPOptions = array(
                    'ssl' => array(
                        'verify_peer' => false,
                        'verify_peer_name' => false,
                        'allow_self_signed' => true
                    )
                );

                //Recipients
                $mail->setFrom('publicotavern@gmail.com', 'EcoEstates Registration'); 
                $mail->addAddress($email, $fullname);

                //Content
                $mail->isHTML(true);
                $mail->Subject = 'Your OTP for EcoEstates Registration';
                $mail->Body    = "Hello $fullname,<br><br>Your OTP for registration is: <b style='font-size: 20px; color: #4CAF50;'>$otp</b><br><br>Please enter this code to complete your registration.<br><br>Thank you,<br>EcoEstates Team";
                $mail->AltBody = "Hello $fullname,\n\nYour OTP for registration is: $otp\n\nPlease enter this code to complete your registration.\n\nThank you,\nEcoEstates Team";

                $mail->send();
                $success_msg = "An OTP has been successfully sent to your email address.";
            } catch (Exception $e) {
                // If mail fails, provide the error message
                $error = "Registration email failed to send. Mailer Error: {$mail->ErrorInfo}";
            }
        } else {
            $error = "PHPMailer is not installed or configured correctly.";
        }
    }
} elseif (isset($_POST['verify_otp'])) {
    $submitted_otp = $_POST['otp'];
    
    if (isset($_SESSION['temp_user'])) {
        $_SESSION['temp_user']['attempts']++;
        
        if ($_SESSION['temp_user']['attempts'] > 3) {
            unset($_SESSION['temp_user']);
            $error = "Maximum OTP attempts exceeded. Please register again.";
        } elseif ($submitted_otp == $_SESSION['temp_user']['otp']) {
            // OTP matches, insert into database
            $u = $_SESSION['temp_user'];
            $fullname = $conn->real_escape_string($u['fullname']);
            $phone = $conn->real_escape_string($u['phone']);
            $email = $conn->real_escape_string($u['email']);
            $p = $conn->real_escape_string($u['password']);
            
            $insert = $conn->query("INSERT INTO users (fullname, phone, email, password, role) VALUES ('$fullname', '$phone', '$email', '$p', 'BUYER')");
            if ($insert) {
                unset($_SESSION['temp_user']); // Registration complete, clear session
                header("Location: login.php?success=1");
                exit();
            } else {
                $error = "Registration failed during saving. Please try again.";
            }
        } else {
            $error = "Invalid OTP. Please try again.";
        }
    } else {
        $error = "Session expired or invalid. Please start registration again.";
    }
} elseif (isset($_POST['cancel_registration'])) {
    unset($_SESSION['temp_user']);
    header("Location: register.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register | EcoEstates</title>
    <link rel="stylesheet" href="assets/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body class="login-body">
    
    <div class="login-box">
        <div style="font-size: 40px; margin-bottom: 10px;">🌲</div>
        
        <h2>EcoEstates</h2>
        <span class="version">System v2.0</span>

        <?php if($error): ?>
            <div style="background:#ffebee; color:#c62828; padding:10px; border-radius:6px; font-size:13px; margin-bottom:15px;">
                <?= $error ?>
            </div>
        <?php endif; ?>
        
        <?php if($success_msg): ?>
            <div style="background:#e8f5e9; color:#2e7d32; padding:10px; border-radius:6px; font-size:13px; margin-bottom:15px;">
                <?= $success_msg ?>
            </div>
        <?php endif; ?>

        <?php if(isset($_SESSION['temp_user'])): ?>
            <form method="POST">
                <p style="font-size: 14px; text-align: center; margin-bottom: 15px;">
                    Please enter the 6-digit OTP sent to <b><?= htmlspecialchars($_SESSION['temp_user']['email']) ?></b>.
                </p>
                
                <div class="input-group">
                    <i class="fa-solid fa-key"></i>
                    <input type="text" name="otp" placeholder="6-digit OTP" required pattern="\d{6}" maxlength="6">
                </div>

                <button type="submit" name="verify_otp" class="btn-login" style="margin-bottom: 10px;">
                    VERIFY OTP & REGISTER
                </button>
                
                <button type="submit" name="cancel_registration" class="btn-login" style="background-color: #f44336;">
                    CANCEL
                </button>
            </form>
        <?php else: ?>
            <form method="POST">
                <div class="input-group">
                    <i class="fa-solid fa-users-gear"></i>
                    <input type="text" name="fullname" placeholder="Full Name" required>
                </div>

                <div class="input-group">
                    <i class="fa-solid fa-phone"></i>
                    <input type="text" name="phone" placeholder="Phone Number" required>
                </div>

                <div class="input-group">
                    <i class="fa-solid fa-envelope"></i>
                    <input type="email" name="email" placeholder="Email Address" required>
                </div>

                <div class="input-group">
                    <i class="fa-solid fa-lock"></i>
                    <input type="password" name="password" placeholder="Password" required>
                </div>

                <button type="submit" name="register" class="btn-login">
                    REGISTER NOW
                </button>
            </form>

            <div class="small-text">
                Already have an account? <a href="login.php">Login here</a><br><br>
                Go back to <a href="index.php">Website Homepage</a>
            </div>
        <?php endif; ?>
    </div>

</body>
</html>