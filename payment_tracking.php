<?php
// payment_tracking.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    header("Location: login.php");
    exit();
}

$alert_msg = "";
$alert_type = "";

// --- CHECK DATABASE STRUCTURE (Failsafe) ---
$has_res_id_col = false;
$colCheck = $conn->query("SHOW COLUMNS FROM transactions LIKE 'reservation_id'");
if($colCheck && $colCheck->num_rows > 0) {
    $has_res_id_col = true;
}

// --- HANDLE RECORDING DOWN PAYMENT ---
if(isset($_POST['record_payment'])){
    $res_id = (int)$_POST['res_id'];
    $amt = floatval($_POST['amount']);
    $date = $_POST['trans_date'];
    $remarks = htmlspecialchars($_POST['remarks']);
    
    // Auto-generate OR number if blank
    $or_num = !empty($_POST['or_number']) ? htmlspecialchars($_POST['or_number']) : 'DP-' . strtoupper(uniqid());
    $desc = "Down Payment for Res#$res_id" . (!empty($remarks) ? " - $remarks" : "");

    if($amt > 0){
        try {
            // Check for duplicate OR number
            $check_stmt = $conn->prepare("SELECT id FROM transactions WHERE or_number = ?");
            $check_stmt->bind_param("s", $or_num);
            $check_stmt->execute();
            
            if($check_stmt->get_result()->num_rows > 0) {
                $alert_msg = "Error: The OR / Reference Number '<b>$or_num</b>' is already in use.";
                $alert_type = "error";
            } else {
                // Insert Payment (Uses reservation_id if the database is upgraded, otherwise falls back to safe text matching)
                if ($has_res_id_col) {
                    $stmt = $conn->prepare("INSERT INTO transactions (reservation_id, type, amount, transaction_date, description, or_number) VALUES (?, 'INCOME', ?, ?, ?, ?)");
                    $stmt->bind_param("idsss", $res_id, $amt, $date, $desc, $or_num);
                } else {
                    $stmt = $conn->prepare("INSERT INTO transactions (type, amount, transaction_date, description, or_number) VALUES ('INCOME', ?, ?, ?, ?)");
                    $stmt->bind_param("dsss", $amt, $date, $desc, $or_num);
                }
                
                if($stmt->execute()) {
                    $alert_msg = "Payment of ₱" . number_format($amt, 2) . " successfully recorded!";
                    $alert_type = "success";
                } else {
                    $alert_msg = "Failed to record payment. Please try again.";
                    $alert_type = "error";
                }
            }
        } catch (Exception $e) {
            $alert_msg = "Database Error: " . $e->getMessage();
            $alert_type = "error";
        }
    } else {
        $alert_msg = "Amount must be greater than zero.";
        $alert_type = "error";
    }
}

// --- HANDLE SEND REMINDER EMAIL ---
if(isset($_POST['send_reminder'])){
    $res_id = (int)$_POST['res_id'];
    $remaining_dp = floatval($_POST['remaining_dp']); 
    
    $resData = $conn->query("
        SELECT r.*, u.email, u.fullname, l.block_no, l.lot_no, l.total_price 
        FROM reservations r 
        JOIN users u ON r.user_id = u.id 
        JOIN lots l ON r.lot_id = l.id 
        WHERE r.id='$res_id'
    ")->fetch_assoc();

    if($resData && $remaining_dp > 0){
        $res_time = strtotime($resData['reservation_date']);
        $deadline_exact = date('F j, Y \a\t g:i A', strtotime('+20 days', $res_time));
        $formatted_remaining = number_format($remaining_dp, 2);
        
        require 'PHPMailer/Exception.php';
        require 'PHPMailer/PHPMailer.php';
        require 'PHPMailer/SMTP.php';
        
        $mail = new PHPMailer\PHPMailer\PHPMailer();
        try {
            $mail->isSMTP();
            $mail->Host       = 'smtp.gmail.com'; 
            $mail->SMTPAuth   = true;
            $mail->Username   = 'publicotavern@gmail.com'; 
            $mail->Password   = 'xcvgrzzsjvnbtsti';    
            $mail->SMTPSecure = 'tls';
            $mail->Port       = 587;
            $mail->SMTPOptions = array('ssl' => array('verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true));

            $mail->setFrom('publicotavern@gmail.com', 'JEJ Surveying');
            $mail->addAddress($resData['email']);

            $mail->isHTML(true);
            $mail->Subject = 'ACTION REQUIRED: Down Payment Balance Deadline - JEJ Surveying';
            
            $mail->Body = "
            <div style='font-family: Arial, sans-serif; color: #334155; max-width: 600px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.05);'>
                <div style='background-color: #2e7d32; padding: 20px; text-align: center; color: white;'>
                    <h2 style='margin: 0; font-size: 20px; letter-spacing: 0.5px;'>Property Reservation Update</h2>
                </div>
                <div style='padding: 30px; background-color: #ffffff;'>
                    <p style='font-size: 15px;'>Hello <b>{$resData['fullname']}</b>,</p>
                    <p style='font-size: 15px; line-height: 1.5;'>This is an official notification regarding your approved reservation for <b>Block {$resData['block_no']} Lot {$resData['lot_no']}</b>.</p>
                    <p style='font-size: 15px; line-height: 1.5;'>To fully secure your property, please settle the <b>Remaining Balance</b> of your 20% Down Payment. Please find your payment schedule below:</p>
                    
                    <div style='background-color: #fff1f2; border-left: 4px solid #e11d48; padding: 20px; margin: 25px 0; border-radius: 0 8px 8px 0;'>
                        <h3 style='margin: 0 0 15px 0; color: #be123c; font-size: 16px;'>Payment Details</h3>
                        <table style='width: 100%; font-size: 14px;'>
                            <tr>
                                <td style='padding-bottom: 8px; color: #475569;'>Remaining DP Due:</td>
                                <td style='padding-bottom: 8px; font-weight: bold; color: #0f172a; font-size: 16px;'>₱{$formatted_remaining}</td>
                            </tr>
                            <tr>
                                <td style='color: #475569;'>Strict Deadline:</td>
                                <td style='font-weight: bold; color: #e11d48;'>{$deadline_exact}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <p style='font-size: 14px; color: #64748b; line-height: 1.5;'>Failure to settle this remaining amount by the deadline may result in the forfeiture of your reservation.</p>
                    <hr style='border: none; border-top: 1px solid #e2e8f0; margin: 25px 0;'>
                    <p style='font-size: 14px; margin: 0;'>Thank you,<br><strong style='color: #2e7d32;'>JEJ Surveying Team</strong></p>
                </div>
            </div>";

            $mail->send();
            $alert_msg = "Reminder email with updated balance sent successfully to " . $resData['fullname'];
            $alert_type = "success";
        } catch (Exception $e) {
            $alert_msg = "Failed to send email. Mailer Error: {$mail->ErrorInfo}";
            $alert_type = "error";
        }
    }
}

// --- FETCH & PROCESS APPROVED RESERVATIONS ---
$query = "SELECT r.*, u.fullname, u.email as user_email, l.block_no, l.lot_no, l.total_price 
          FROM reservations r 
          JOIN users u ON r.user_id = u.id 
          JOIN lots l ON r.lot_id = l.id 
          WHERE r.status = 'APPROVED' 
          ORDER BY r.reservation_date DESC";
$res = $conn->query($query);

$approved_reservations = [];
$overdue_count = 0;
$due_soon_count = 0;

if($res && $res->num_rows > 0) {
    while($row = $res->fetch_assoc()){
        
        $dp_total_required = round($row['total_price'] * 0.20, 2);
        
        // Fetch total DP paid for this specific reservation safely
        if ($has_res_id_col) {
            $dp_query = $conn->prepare("SELECT SUM(amount) as total_paid FROM transactions WHERE type='INCOME' AND reservation_id = ?");
            $dp_query->bind_param("i", $row['id']);
        } else {
            $desc_like = "%Down Payment%Res#{$row['id']}%";
            $dp_query = $conn->prepare("SELECT SUM(amount) as total_paid FROM transactions WHERE type='INCOME' AND description LIKE ?");
            $dp_query->bind_param("s", $desc_like);
        }
        
        $dp_query->execute();
        $dp_result = $dp_query->get_result()->fetch_assoc();
        
        $dp_paid_amount = $dp_result['total_paid'] ? floatval($dp_result['total_paid']) : 0;
        $dp_remaining = $dp_total_required - $dp_paid_amount;
        
        $row['dp_total_required'] = $dp_total_required;
        $row['dp_paid_amount'] = $dp_paid_amount;
        $row['dp_remaining'] = $dp_remaining > 0 ? $dp_remaining : 0;
        $row['is_dp_fully_paid'] = ($dp_remaining <= 0);

        // Calculate Deadlines
        if (!empty($row['reservation_date'])) {
            $res_time = strtotime($row['reservation_date']);
            $deadline_timestamp = strtotime('+20 days', $res_time);
            $row['deadline_formatted'] = date('M d, Y g:i A', $deadline_timestamp);
            
            // Flag overdue only if DP is NOT fully paid
            if (!$row['is_dp_fully_paid']) {
                $days_left = ($deadline_timestamp - time()) / (60 * 60 * 24);
                $row['is_overdue'] = ($days_left < 0);
                $row['is_due_soon'] = ($days_left >= 0 && $days_left <= 3);
                
                if($row['is_overdue']) $overdue_count++;
                if($row['is_due_soon']) $due_soon_count++;
            } else {
                $row['is_overdue'] = false;
                $row['is_due_soon'] = false;
            }
        } else {
            $row['deadline_formatted'] = "Date Error";
            $row['is_overdue'] = false;
            $row['is_due_soon'] = false;
        }

        $approved_reservations[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment Tracking | JEJ Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <style>
        :root {
            /* NATURE GREEN THEME */
            --primary: #2e7d32; 
            --primary-light: #e8f5e9; 
            --dark: #1b5e20; 
            --gray-light: #f1f8e9; 
            --gray-border: #c8e6c9; 
            --text-muted: #607d8b; 
            
            --shadow-sm: 0 1px 2px 0 rgba(46, 125, 50, 0.08);
            --shadow-md: 0 4px 6px -1px rgba(46, 125, 50, 0.1), 0 2px 4px -1px rgba(46, 125, 50, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(46, 125, 50, 0.15), 0 4px 6px -2px rgba(46, 125, 50, 0.05);
        }

        body { background-color: #fafcf9; display: flex; min-height: 100vh; overflow-x: hidden; font-family: 'Inter', sans-serif; color: #37474f; margin: 0; }

        .sidebar { width: 260px; background: #ffffff; border-right: 1px solid var(--gray-border); display: flex; flex-direction: column; position: fixed; height: 100vh; z-index: 100; box-shadow: var(--shadow-sm); }
        .brand-box { padding: 25px; border-bottom: 1px solid var(--gray-border); display: flex; align-items: center; gap: 12px; }
        .sidebar-menu { padding: 20px 15px; flex: 1; overflow-y: auto; }
        .menu-link { display: flex; align-items: center; gap: 12px; padding: 12px 18px; color: #455a64; text-decoration: none; font-weight: 500; font-size: 14px; border-radius: 10px; margin-bottom: 6px; transition: all 0.2s ease; }
        .menu-link:hover { background: var(--gray-light); color: var(--primary); }
        .menu-link.active { background: var(--primary-light); color: var(--primary); font-weight: 600; border-left: 4px solid var(--primary); }
        .menu-link i { width: 20px; text-align: center; font-size: 16px; opacity: 0.8; }
        
        .main-panel { margin-left: 260px; flex: 1; padding: 0; width: calc(100% - 260px); display: flex; flex-direction: column; }
        
        .top-header { display: flex; justify-content: space-between; align-items: center; background: #ffffff; padding: 20px 40px; border-bottom: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); z-index: 50; }
        .header-title h1 { font-size: 22px; font-weight: 800; color: var(--dark); margin: 0 0 4px 0; letter-spacing: -0.5px;}
        .header-title p { color: var(--text-muted); font-size: 13px; margin: 0; }

        .profile-dropdown { position: relative; cursor: pointer; }
        .profile-trigger { display: flex; align-items: center; gap: 12px; padding: 6px 12px; border-radius: 10px; transition: background 0.2s; border: 1px solid transparent; }
        .profile-trigger:hover { background: var(--gray-light); border-color: var(--gray-border); }
        .profile-avatar { width: 40px; height: 40px; background: var(--primary); color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 16px; box-shadow: 0 2px 4px rgba(46, 125, 50, 0.2);}
        .profile-info strong { display: block; font-size: 13px; color: var(--dark); line-height: 1.2; }
        .profile-info small { font-size: 11px; color: var(--text-muted); font-weight: 500; }
        
        .dropdown-menu { display: none; position: absolute; right: 0; top: 110%; background: white; border-radius: 12px; box-shadow: var(--shadow-lg); border: 1px solid var(--gray-border); min-width: 200px; z-index: 1000; overflow: hidden; transform-origin: top right; animation: dropAnim 0.2s ease-out forwards; }
        @keyframes dropAnim { 0% { opacity: 0; transform: scale(0.95) translateY(-10px); } 100% { opacity: 1; transform: scale(1) translateY(0); } }
        .profile-dropdown:hover .dropdown-menu { display: block; }
        .dropdown-header { padding: 15px; border-bottom: 1px solid var(--gray-border); background: var(--gray-light); }
        .dropdown-item { padding: 12px 16px; display: flex; align-items: center; gap: 12px; color: #455a64; text-decoration: none; font-size: 13px; font-weight: 500; transition: background 0.2s; border-left: 3px solid transparent;}
        .dropdown-item:hover { background: var(--primary-light); color: var(--primary); border-left-color: var(--primary); }
        .dropdown-item.text-danger { color: #d84315; }
        .dropdown-item.text-danger:hover { background: #fbe9e7; color: #bf360c; border-left-color: #d84315; }

        .content-area { padding: 35px 40px; flex: 1; }

        .alert-banner { padding: 16px 20px; border-radius: 10px; margin-bottom: 25px; font-weight: 500; font-size: 14px; box-shadow: var(--shadow-sm); display: flex; align-items: center; gap: 12px;}
        .alert-success { background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; }
        .alert-error { background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }
        
        .urgent-banner { background: #fef2f2; border-left: 5px solid #ef4444; padding: 20px; border-radius: 8px; margin-bottom: 30px; box-shadow: var(--shadow-sm); display: flex; align-items: flex-start; gap: 15px; }
        .urgent-banner i { color: #ef4444; font-size: 24px; margin-top: 2px;}

        .table-container { background: white; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); overflow: hidden; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px 20px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; background: var(--gray-light); border-bottom: 1px solid var(--gray-border); letter-spacing: 0.5px;}
        td { padding: 16px 20px; border-bottom: 1px solid var(--gray-border); color: #37474f; font-size: 13px; vertical-align: top; }
        tr:hover td { background: #fdfdfd; }
        tr:last-child td { border-bottom: none; }

        .badge { padding: 5px 10px; border-radius: 6px; font-size: 10px; font-weight: 800; text-transform: uppercase; display: inline-block;}
        .badge-full { background: #d1fae5; color: #059669; border: 1px solid #a7f3d0; } /* Emerald */
        .badge-partial { background: #dbeafe; color: #2563eb; border: 1px solid #bfdbfe; } /* Blue */
        .badge-none { background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; } /* Slate */
        
        .tag-overdue { background: #fee2e2; color: #be123c; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 800; text-transform: uppercase; margin-top: 5px; display: inline-block; border: 1px solid #fecdd3;}
        .tag-soon { background: #fef3c7; color: #b45309; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 800; text-transform: uppercase; margin-top: 5px; display: inline-block; border: 1px solid #fde68a;}

        .btn-action { padding: 8px 14px; border-radius: 6px; font-size: 12px; font-weight: 700; cursor: pointer; transition: 0.2s; border: none; display: inline-flex; align-items: center; justify-content: center; gap: 6px; text-decoration: none;}
        .btn-record { background: #10b981; color: white; box-shadow: 0 2px 4px rgba(16, 185, 129, 0.2); }
        .btn-record:hover { background: #059669; transform: translateY(-1px); }
        .btn-remind { background: #ef4444; color: white; box-shadow: 0 2px 4px rgba(239, 68, 68, 0.2); }
        .btn-remind:hover { background: #dc2626; transform: translateY(-1px); }
        .btn-billing { background: #3b82f6; color: white; box-shadow: 0 2px 4px rgba(59, 130, 246, 0.2);}
        .btn-billing:hover { background: #2563eb; transform: translateY(-1px); }
        .btn-edit-terms { background: #f59e0b; color: white; box-shadow: 0 2px 4px rgba(245, 158, 11, 0.2);}
        .btn-edit-terms:hover { background: #d97706; transform: translateY(-1px); }

        /* Modal Styles */
        .modal { display: none; position: fixed; z-index: 9999; inset: 0; background: rgba(0, 0, 0, 0.6); backdrop-filter: blur(3px); padding: 30px; overflow-y: auto; align-items: center; justify-content: center;}
        .modal-content { width: 100%; max-width: 450px; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.3); animation: dropAnim 0.2s ease-out forwards;}
        .modal-header { padding: 20px 25px; border-bottom: 1px solid var(--gray-border); display: flex; justify-content: space-between; align-items: center; background: var(--gray-light); }
        .modal-header h2 { margin: 0; font-size: 18px; font-weight: 700; color: var(--dark); }
        .close-btn { background: none; border: none; font-size: 20px; color: #90a4ae; cursor: pointer; transition: 0.2s;}
        .close-btn:hover { color: #ef4444; transform: scale(1.1);}
        
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; font-size: 13px; font-weight: 600; color: #455a64; margin-bottom: 6px; }
        .form-control { width: 100%; padding: 10px 14px; border: 1px solid #cbd5e1; border-radius: 8px; font-family: inherit; font-size: 14px; outline: none; transition: 0.2s; box-sizing: border-box;}
        .form-control:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.15); }
    </style>
</head>
<body>

    <div class="sidebar">
        <div class="brand-box">
            <img src="assets/logo.png" style="height: 38px; width: auto; border-radius: 8px;">
            <div style="line-height: 1.1;">
                <span style="font-size: 16px; font-weight: 800; color: var(--primary); display: block;">JEJ Surveying</span>
                <span style="font-size: 11px; color: var(--text-muted); font-weight: 500;">Management Portal</span>
            </div>
        </div>
        
        <div class="sidebar-menu">
            <small style="padding: 0 15px; color: #90a4ae; font-weight: 700; font-size: 11px; display: block; margin-bottom: 12px; letter-spacing: 0.5px;">MAIN MENU</small>
            <a href="admin.php?view=dashboard" class="menu-link"><i class="fa-solid fa-chart-pie"></i> Dashboard</a>
            <a href="reservation.php" class="menu-link"><i class="fa-solid fa-file-signature"></i> Reservations</a>
            <a href="master_list.php" class="menu-link"><i class="fa-solid fa-map-location-dot"></i> Master List / Map</a>
            <a href="admin.php?view=inventory" class="menu-link"><i class="fa-solid fa-plus-circle"></i> Add Property</a>
            <a href="financial.php" class="menu-link"><i class="fa-solid fa-coins"></i> Financials</a>
            <a href="payment_tracking.php" class="menu-link active"><i class="fa-solid fa-file-invoice-dollar"></i> Payment Tracking</a>
            
            <small style="padding: 0 15px; color: #90a4ae; font-weight: 700; font-size: 11px; display: block; margin-top: 25px; margin-bottom: 12px; letter-spacing: 0.5px;">MANAGEMENT</small>
            <a href="accounts.php" class="menu-link"><i class="fa-solid fa-users-gear"></i> Accounts</a>
            <a href="delete_history.php" class="menu-link"><i class="fa-solid fa-trash-can"></i> Delete History</a>
            
            <small style="padding: 0 15px; color: #90a4ae; font-weight: 700; font-size: 11px; display: block; margin-top: 25px; margin-bottom: 12px; letter-spacing: 0.5px;">SYSTEM</small>
            <a href="index.php" class="menu-link" target="_blank"><i class="fa-solid fa-globe"></i> View Website</a>
        </div>
    </div>

    <div class="main-panel">
        
        <div class="top-header">
            <div class="header-title">
                <h1>Payment Tracking</h1>
                <p>Track buyer payment terms, record down payments, and send deadline reminders.</p>
            </div>
            
            <div class="profile-dropdown">
                <div class="profile-trigger">
                    <div class="profile-avatar">A</div>
                    <div class="profile-info">
                        <strong>Administrator</strong>
                        <small>System Admin <i class="fa-solid fa-chevron-down" style="font-size: 9px; margin-left: 3px;"></i></small>
                    </div>
                </div>
                
                <div class="dropdown-menu">
                    <div class="dropdown-header">
                        <strong style="display: block; font-size: 13px; color: var(--dark);">JEJ Admin System</strong>
                        <span style="font-size: 11px; color: var(--text-muted);">Logged in successfully</span>
                    </div>
                    <a href="audit_logs.php" class="dropdown-item"><i class="fa-solid fa-clock-rotate-left" style="width:16px;"></i> System Audit Logs</a>
                    <a href="settings.php" class="dropdown-item"><i class="fa-solid fa-gear" style="width:16px;"></i> Account Settings</a>
                    <div style="height: 1px; background: var(--gray-border); margin: 5px 0;"></div>
                    <a href="logout.php" class="dropdown-item text-danger"><i class="fa-solid fa-arrow-right-from-bracket" style="width:16px;"></i> Secure Logout</a>
                </div>
            </div>
        </div>

        <div class="content-area">

            <?php if($alert_msg): ?>
                <div class="alert-banner <?= $alert_type=='success' ? 'alert-success' : 'alert-error' ?>">
                    <i class="fa-solid <?= $alert_type=='success'?'fa-check-circle':'fa-exclamation-circle' ?>"></i>
                    <?= $alert_msg ?>
                </div>
            <?php endif; ?>

            <?php if($overdue_count > 0 || $due_soon_count > 0): ?>
                <div class="urgent-banner">
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    <div>
                        <strong style="color: #b91c1c; font-size: 16px; display: block; margin-bottom: 4px;">PAYMENT ATTENTION REQUIRED</strong>
                        <div style="color: #b91c1c; font-size: 14px; line-height: 1.5;">
                            <?php if($overdue_count > 0): ?>
                                <b><?= $overdue_count ?></b> reservation(s) have <b style="text-decoration: underline;">overdue</b> Down Payments.<br>
                            <?php endif; ?>
                            <?php if($due_soon_count > 0): ?>
                                <b><?= $due_soon_count ?></b> reservation(s) have Down Payments due in the next 3 days.<br>
                            <?php endif; ?>
                            <span style="font-size: 12px; color: #dc2626; display: block; margin-top: 5px;">Please send reminder emails to these buyers to secure their reservations.</span>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 22%;">Buyer Info</th>
                            <th style="width: 18%;">Property</th>
                            <th style="width: 25%;">Financials & Deadline</th>
                            <th style="width: 15%;">DP Status</th>
                            <th style="width: 20%;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if(!empty($approved_reservations)): ?>
                            <?php foreach($approved_reservations as $row): 
                                $balance = $row['total_price'] - $row['dp_paid_amount'];
                            ?>
                            <tr>
                                <td>
                                    <strong style="color: #1e293b; font-size: 14px;"><?= htmlspecialchars($row['fullname']) ?></strong><br>
                                    <span style="font-size: 12px; color: #64748b;"><i class="fa-regular fa-envelope" style="margin-right:3px;"></i> <?= $row['email'] ?? $row['user_email'] ?></span>
                                </td>
                                <td>
                                    <strong style="color: var(--primary); font-size: 13px;">Block <?= $row['block_no'] ?> Lot <?= $row['lot_no'] ?></strong>
                                </td>
                                <td>
                                    <div style="font-size: 12px; margin-bottom: 4px; color: #475569;">TCP: <strong>₱<?= number_format($row['total_price'], 2) ?></strong></div>
                                    
                                    <div style="font-size: 12px; margin-bottom: 4px; color: #334155;">
                                        20% DP Target: <strong>₱<?= number_format($row['dp_total_required'], 2) ?></strong>
                                    </div>
                                    
                                    <div style="font-size: 12px; margin-bottom: 4px; color: #059669; font-weight: 700;">
                                        Paid: ₱<?= number_format($row['dp_paid_amount'], 2) ?>
                                    </div>

                                    <?php if(!$row['is_dp_fully_paid']): ?>
                                        <div style="font-size: 12px; margin-bottom: 4px; color: #e11d48; font-weight: 700;">
                                            Due: ₱<?= number_format($row['dp_remaining'], 2) ?>
                                        </div>

                                        <div style="margin-top: 10px; padding-top: 10px; border-top: 1px dashed #cbd5e1;">
                                            <div style="font-size: 10px; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin-bottom: 3px;">DP Deadline:</div>
                                            <div style="font-size: 12px; font-weight: <?= ($row['is_overdue'] || $row['is_due_soon']) ? '800' : '600' ?>; color: <?= $row['is_overdue'] ? '#e11d48' : ($row['is_due_soon'] ? '#d97706' : '#334155') ?>;">
                                                <i class="fa-regular fa-clock" style="margin-right: 3px;"></i> <?= $row['deadline_formatted'] ?>
                                            </div>
                                            <?php if($row['is_overdue']): ?>
                                                <span class="tag-overdue"><i class="fa-solid fa-triangle-exclamation"></i> Overdue</span>
                                            <?php elseif($row['is_due_soon']): ?>
                                                <span class="tag-soon"><i class="fa-solid fa-clock-rotate-left"></i> Due Soon</span>
                                            <?php endif; ?>
                                        </div>
                                    <?php else: ?>
                                        <div style="font-size: 11px; color: #64748b; margin-top: 6px; padding-top: 6px; border-top: 1px dashed #cbd5e1;">
                                            Remaining TCP Balance: ₱<?= number_format($balance, 2) ?>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if($row['is_dp_fully_paid']): ?>
                                        <span class="badge badge-full"><i class="fa-solid fa-check"></i> DP Fully Paid</span>
                                    <?php elseif($row['dp_paid_amount'] > 0): ?>
                                        <span class="badge badge-partial"><i class="fa-solid fa-spinner"></i> Partial DP</span>
                                    <?php else: ?>
                                        <span class="badge badge-none"><i class="fa-solid fa-xmark"></i> No Payment</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <div style="display: flex; flex-direction: column; gap: 8px;">
                                        <?php if ($row['is_dp_fully_paid']): ?>
                                            <button type="button" class="btn-action btn-billing" 
                                                    data-id="<?= (int)$row['id'] ?>" 
                                                    data-name="<?= htmlspecialchars($row['fullname']) ?>" 
                                                    onclick="showBillingModal(this)">
                                                <i class="fa-solid fa-file-invoice"></i> Show Billing
                                            </button>
                                            <a href="payment_terms.php?res_id=<?= $row['id'] ?>" class="btn-action btn-edit-terms">
                                                <i class="fa-solid fa-pen-to-square"></i> Edit Terms
                                            </a>
                                        <?php else: ?>
                                            <button type="button" class="btn-action btn-record" 
                                                    data-id="<?= (int)$row['id'] ?>" 
                                                    data-balance="<?= $row['dp_remaining'] ?>" 
                                                    data-name="<?= htmlspecialchars($row['fullname']) ?>" 
                                                    onclick="openPaymentModal(this)">
                                                <i class="fa-solid fa-cash-register"></i> Record DP
                                            </button>
                                            
                                            <form method="POST" onsubmit="return confirm('Send an urgent reminder email with the EXACT remaining balance (₱<?= number_format($row['dp_remaining'], 2) ?>)?');">
                                                <input type="hidden" name="res_id" value="<?= (int)$row['id'] ?>">
                                                <input type="hidden" name="remaining_dp" value="<?= $row['dp_remaining'] ?>">
                                                <button type="submit" name="send_reminder" class="btn-action btn-remind" style="width: 100%;">
                                                    <i class="fa-solid fa-envelope"></i> Remind Buyer
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr><td colspan="5" style="text-align: center; padding: 40px; color: #94a3b8;"><i class="fa-solid fa-folder-open" style="font-size: 30px; margin-bottom: 10px; display: block; color: #cbd5e1;"></i>No approved reservations found.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div id="paymentModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2><i class="fa-solid fa-cash-register" style="color: #10b981; margin-right: 5px;"></i> Record Down Payment</h2>
                    <button type="button" class="close-btn" onclick="closePaymentModal()"><i class="fa-solid fa-xmark"></i></button>
                </div>
                <form method="POST" style="padding: 25px;">
                    <input type="hidden" name="res_id" id="modal_res_id">
                    
                    <div style="background: #f1f8e9; border: 1px solid #c8e6c9; padding: 12px; border-radius: 8px; margin-bottom: 20px;">
                        <span style="font-size: 12px; color: #2e7d32; font-weight: 700; display: block; margin-bottom: 4px;">Recording payment for:</span>
                        <strong id="modal_buyer_name" style="color: #1b5e20; font-size: 15px;"></strong>
                    </div>

                    <div class="form-group">
                        <label>Payment Amount (₱)</label>
                        <input type="number" step="0.01" name="amount" id="modal_amount" class="form-control" required>
                        <small style="color: #64748b; font-size: 11px; margin-top: 4px; display: block;">Auto-filled with remaining balance. You can change this for partial payments.</small>
                    </div>
                    <div class="form-group">
                        <label>Date Received</label>
                        <input type="date" name="trans_date" class="form-control" value="<?= date('Y-m-d') ?>" required>
                    </div>
                    <div class="form-group">
                        <label>OR / Reference Number</label>
                        <input type="text" name="or_number" class="form-control" placeholder="E.g., GCASH-12345 or Leave blank to auto-generate">
                    </div>
                    <div class="form-group">
                        <label>Remarks / Payment Method</label>
                        <input type="text" name="remarks" class="form-control" placeholder="E.g., Paid via GCash, Bank Transfer...">
                    </div>
                    
                    <div style="margin-top: 25px; text-align: right; border-top: 1px solid var(--gray-border); padding-top: 15px;">
                        <button type="button" onclick="closePaymentModal()" style="background:#f1f5f9; color:#475569; border: 1px solid #cbd5e1; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer; margin-right: 10px;">Cancel</button>
                        <button type="submit" name="record_payment" style="background:#10b981; color:white; border: none; padding: 10px 24px; border-radius: 8px; font-weight: 600; cursor: pointer;"><i class="fa-solid fa-save"></i> Save Payment</button>
                    </div>
                </form>
            </div>
        </div>

        <div id="billingModal" class="modal" style="background:rgba(15, 23, 42, 0.6); backdrop-filter: blur(3px);">
            <div class="modal-content" style="max-width:900px; width:96vw; max-height:88vh; overflow:auto; padding:0;">
                <div class="modal-header">
                    <h2 style="color: #1e293b;">Statement of Account</h2>
                    <button type="button" class="close-btn" onclick="closeBillingModal()"><i class="fa-solid fa-xmark"></i></button>
                </div>
                <div id="billingContent" style="padding: 20px;">
                    <div style="text-align:center; color:#64748b; padding: 40px;"><i class="fa-solid fa-spinner fa-spin" style="font-size: 24px; margin-bottom: 10px; display: block;"></i> Loading statement...</div>
                </div>
            </div>
        </div>

        <script>
        // Bulletproof function using HTML attributes to prevent string escape errors
        function openPaymentModal(btn) {
            document.getElementById('modal_res_id').value = btn.dataset.id;
            document.getElementById('modal_buyer_name').innerText = btn.dataset.name;
            document.getElementById('modal_amount').value = btn.dataset.balance;
            document.getElementById('paymentModal').style.display = 'flex';
        }
        function closePaymentModal() {
            document.getElementById('paymentModal').style.display = 'none';
        }

        // Bulletproof function using HTML attributes
        function showBillingModal(btn) {
            var modal = document.getElementById('billingModal');
            var content = document.getElementById('billingContent');
            modal.style.display = 'flex';
            content.innerHTML = '<div style="text-align:center; color:#64748b; padding: 40px;"><i class="fa-solid fa-spinner fa-spin" style="font-size: 24px; margin-bottom: 10px; display: block;"></i> Loading statement for ' + btn.dataset.name + '...</div>';

            var xhr = new XMLHttpRequest();
            xhr.open('GET', 'statement_of_account.php?res_id=' + encodeURIComponent(btn.dataset.id), true);
            xhr.onload = function() {
                if (xhr.status === 200) {
                    content.innerHTML = xhr.responseText;
                } else {
                    content.innerHTML = '<div style="color:#e11d48; text-align:center; padding: 30px;">Failed to load billing info.</div>';
                }
            };
            xhr.onerror = function() {
                content.innerHTML = '<div style="color:#e11d48; text-align:center; padding: 30px;">Server communication error while loading billing info.</div>';
            };
            xhr.send();
        }
        function closeBillingModal() {
            document.getElementById('billingModal').style.display = 'none';
        }

        window.addEventListener('click', function(e) {
            if (e.target === document.getElementById('billingModal')) closeBillingModal();
            if (e.target === document.getElementById('paymentModal')) closePaymentModal();
        });
        </script>
    </div>
</body>
</html>