<?php
// actions.php
include 'config.php';

$action = $_POST['action'] ?? '';

// --- USER ACTIONS ---
if($action == 'reserve'){
    checkLogin();
    $user_id = $_SESSION['user_id'];
    $lot_id = $_POST['lot_id'];
    
    // Captured Fields
    $contact = $_POST['contact_number'];
    $birth = $_POST['birth_date'];
    $address = $_POST['address'];
    
    // Helper function for uploads
    function uploadFile($fileInputName){
        $target_dir = "uploads/";
        if(!is_dir($target_dir)) mkdir($target_dir);
        $filename = time() . "_" . basename($_FILES[$fileInputName]["name"]);
        move_uploaded_file($_FILES[$fileInputName]["tmp_name"], $target_dir . $filename);
        return $filename;
    }

    $valid_id_file = uploadFile('valid_id');
    $selfie_id_file = uploadFile('selfie_id');
    $proof_file = uploadFile('proof');

    $stmt = $conn->prepare("INSERT INTO reservations 
        (user_id, lot_id, contact_number, birth_date, buyer_address, payment_proof, valid_id_file, selfie_with_id, status) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')");
    
    $stmt->bind_param("iissssss", $user_id, $lot_id, $contact, $birth, $address, $proof_file, $valid_id_file, $selfie_id_file);
    
    if($stmt->execute()){
        $conn->query("UPDATE lots SET status='RESERVED' WHERE id='$lot_id'");
        header("Location: index.php?msg=verification_submitted");
    } else {
        echo "Error: " . $conn->error;
    }
}

// --- ADMIN ACTIONS ---

if(isset($_POST['action']) && $_POST['action'] == 'approve_res'){
    $res_id = $_POST['res_id'];
    $lot_id = $_POST['lot_id'];
    $admin_id = $_SESSION['user_id'];
    
    // 1. Update Reservation and Lot Status
    $conn->query("UPDATE reservations SET status='APPROVED' WHERE id='$res_id'");
    $conn->query("UPDATE lots SET status='SOLD' WHERE id='$lot_id'");
    
    // 2. Fetch Data for Financial Entry and Email Notification
    $resData = $conn->query("
        SELECT r.*, u.email, u.fullname, l.block_no, l.lot_no, l.total_price 
        FROM reservations r 
        JOIN users u ON r.user_id = u.id 
        JOIN lots l ON r.lot_id = l.id 
        WHERE r.id='$res_id'
    ")->fetch_assoc();
    
    $amount = $resData['total_price'];
    $desc = "Payment for Lot (Block {$resData['block_no']} Lot {$resData['lot_no']}) - Res#$res_id";

    // 3. Ensure 'Lot Sales' Category Exists or get its ID
    $catQuery = $conn->query("SELECT id FROM accounting_categories WHERE name='Lot Sales' LIMIT 1");
    if($catQuery && $catQuery->num_rows > 0){
        $cat_id = $catQuery->fetch_assoc()['id'];
    } else {
        $conn->query("INSERT INTO accounting_categories (name, group_name, type) VALUES ('Lot Sales', 'Income', 'INCOME')");
        $cat_id = $conn->insert_id;
    }

    // Ensure 'General Operations' Project Exists
    $projQuery = $conn->query("SELECT id FROM projects LIMIT 1");
    if($projQuery && $projQuery->num_rows > 0){
        $proj_id = $projQuery->fetch_assoc()['id'];
    } else {
        $conn->query("INSERT INTO projects (name) VALUES ('General Operations')");
        $proj_id = $conn->insert_id;
    }

    // 4. Generate OR Number and Insert Transaction
    $or_number = generateORNumber($conn);
    $date = date('Y-m-d');
    $type = 'INCOME';

    $stmt = $conn->prepare("INSERT INTO transactions (or_number, transaction_date, type, category_id, project_id, amount, description, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssiidsi", $or_number, $date, $type, $cat_id, $proj_id, $amount, $desc, $admin_id);
    
    if($stmt->execute()){
        // 5. Log Activity
        logActivity($conn, $admin_id, "Approved Reservation & Recorded Income", "Res ID: $res_id | Amount: ₱" . number_format($amount, 2));
    }
    
    // 6. SEND EMAIL TO USER VIA PHPMAILER (Using settings from register.php)
    require 'PHPMailer/Exception.php';
    require 'PHPMailer/PHPMailer.php';
    require 'PHPMailer/SMTP.php';
    
    $mail = new PHPMailer\PHPMailer\PHPMailer();
    try {
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com'; 
        $mail->SMTPAuth   = true;
        
        // Exact credentials from your register.php
        $mail->Username   = 'publicotavern@gmail.com'; 
        $mail->Password   = 'xcvgrzzsjvnbtsti';   
        
        $mail->SMTPSecure = 'tls'; 
        $mail->Port       = 587;

        // Bypass SSL certificate verification for local environments
        $mail->SMTPOptions = array(
            'ssl' => array(
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true
            )
        );

        $mail->setFrom('publicotavern@gmail.com', 'JEJ Surveying');
        $mail->addAddress($resData['email']); 

        $mail->isHTML(true);
        $mail->Subject = 'Reservation Approved - Next Steps';
        $mail->Body    = "Hello {$resData['fullname']},<br><br>Congratulations! Your reservation for <b>Block {$resData['block_no']} Lot {$resData['lot_no']}</b> has been approved.<br><br>Please be reminded that you need to pay the <b>Down Payment within 20 days</b> to secure your property fully.<br><br>Thank you,<br>JEJ Surveying Team";

        $mail->send();
    } catch (Exception $e) {
        // Continue script execution even if email fails
        error_log("Email sending failed: " . $mail->ErrorInfo);
    }

    // 7. Redirect to the new Payment Terms Setup page
    header("Location: payment_terms.php?res_id=$res_id");
    exit();
}

if(isset($_POST['action']) && $_POST['action'] == 'reject_res'){
    $res_id = $_POST['res_id'];
    $admin_id = $_SESSION['user_id'];
    
    $row = $conn->query("SELECT lot_id FROM reservations WHERE id='$res_id'")->fetch_assoc();
    $lot_id = $row['lot_id'];
    
    $conn->query("UPDATE reservations SET status='REJECTED' WHERE id='$res_id'");
    $conn->query("UPDATE lots SET status='AVAILABLE' WHERE id='$lot_id'");
    
    logActivity($conn, $admin_id, "Rejected Reservation", "Res ID: $res_id was rejected.");
    
    // Redirect back
    header("Location: reservation.php?status=PENDING&msg=rejected");
    exit();
}
?>