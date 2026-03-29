<?php
// issue_check.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    header("Location: login.php");
    exit();
}

$alert_msg = "";
$alert_type = "";

if($_SERVER['REQUEST_METHOD'] == 'POST'){
    $transaction_date = $_POST['transaction_date'];
    $payee = $_POST['payee'];
    $bank_name = $_POST['bank_name'];
    $check_number = $_POST['check_number'];
    $amount = $_POST['amount'];
    $category_id = $_POST['category_id'];
    $project_id = $_POST['project_id'];
    $description = $_POST['description'];
    $user_id = $_SESSION['user_id'];
    
    // Generate Check Voucher Number
    $cv_number = generateCVNumber($conn);

    $stmt = $conn->prepare("INSERT INTO transactions (or_number, transaction_date, type, category_id, project_id, amount, description, user_id, payee, bank_name, check_number, is_check) VALUES (?, ?, 'EXPENSE', ?, ?, ?, ?, ?, ?, ?, ?, 1)");
    
    // FIXED: Changed "sssiidsisss" to "ssiidsisss" (10 parameters for 10 placeholders)
    $stmt->bind_param("ssiidsisss", $cv_number, $transaction_date, $category_id, $project_id, $amount, $description, $user_id, $payee, $bank_name, $check_number);
    
    if($stmt->execute()){
        logActivity($conn, $user_id, "Issued Check Voucher", "CV: $cv_number | Payee: $payee | Amount: ₱" . number_format($amount, 2));
        echo "<script>
            alert('Check Voucher Saved! Number: $cv_number'); 
            window.open('print_check_voucher.php?cv=$cv_number', '_blank');
            window.location.href = 'financial.php';
        </script>";
        exit();
    } else {
        $alert_msg = "Error generating voucher: " . $conn->error;
        $alert_type = "error";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Issue Check Voucher | JEJ Surveying</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@500;700;800;900&family=Open+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/modern.css">
    <style>
        body { background-color: #F7FAFC; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .form-container { background: white; padding: 40px; border-radius: 16px; border: 1px solid #EDF2F7; box-shadow: var(--shadow-soft); max-width: 800px; width: 100%; }
        .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .input-group { margin-bottom: 15px; }
        .input-group label { display: block; font-size: 12px; font-weight: 700; color: #718096; margin-bottom: 8px; text-transform: uppercase; }
        .form-control { width: 100%; padding: 12px; border: 1px solid #E2E8F0; border-radius: 8px; background: #F9FAFB; font-size: 14px; outline: none; }
        .form-control:focus { background: white; border-color: #805AD5; box-shadow: 0 0 0 3px rgba(128, 90, 213, 0.1); }
        .full-width { grid-column: span 2; }
    </style>
</head>
<body>
    <div class="form-container">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 2px solid #EDF2F7; padding-bottom: 15px;">
            <div>
                <h2 style="font-weight: 800; color: var(--dark); margin: 0; font-size: 22px;"><i class="fa-solid fa-money-check" style="color: #805AD5; margin-right: 10px;"></i>Issue Check Voucher</h2>
                <p style="color: #718096; margin: 5px 0 0 0; font-size: 13px;">Record large land subdividing payouts, titles, and commissions via Check.</p>
            </div>
            <a href="financial.php" style="color: #718096; text-decoration: none; font-weight: 700; font-size: 14px;"><i class="fa-solid fa-xmark" style="font-size: 20px;"></i></a>
        </div>

        <?php if($alert_msg): ?>
            <div style="padding: 15px; border-radius: 10px; margin-bottom: 25px; font-weight: 600; font-size: 14px; background: #FFF5F5; color: #C53030; border: 1px solid #FED7D7;">
                <i class="fa-solid fa-exclamation-circle" style="margin-right: 8px;"></i> <?= $alert_msg ?>
            </div>
        <?php endif; ?>

        <form method="POST">
            <div class="form-grid">
                <div class="input-group">
                    <label>Date Issued</label>
                    <input type="date" name="transaction_date" class="form-control" value="<?= date('Y-m-d') ?>" required>
                </div>
                <div class="input-group">
                    <label>Amount (PHP)</label>
                    <input type="number" step="0.01" name="amount" class="form-control" placeholder="0.00" style="font-weight: 800; color: #E53E3E;" required>
                </div>

                <div class="input-group full-width">
                    <label>Payee Name (Who receives the check)</label>
                    <input type="text" name="payee" class="form-control" placeholder="e.g., John Doe Surveying Services" required>
                </div>

                <div class="input-group">
                    <label>Bank Name</label>
                    <input type="text" name="bank_name" class="form-control" placeholder="e.g., BDO, Metrobank" required>
                </div>
                <div class="input-group">
                    <label>Check Number</label>
                    <input type="text" name="check_number" class="form-control" placeholder="e.g., 000123456" required>
                </div>

                <div class="input-group">
                    <label>Accounting Category</label>
                    <select name="category_id" class="form-control" required>
                        <?php
                        $cats = $conn->query("SELECT * FROM accounting_categories WHERE type='EXPENSE' ORDER BY group_name, name");
                        while($c = $cats->fetch_assoc()){ echo "<option value='{$c['id']}'>[{$c['group_name']}] {$c['name']}</option>"; }
                        ?>
                    </select>
                </div>
                <div class="input-group">
                    <label>Project Assignment</label>
                    <select name="project_id" class="form-control" required>
                        <?php
                        $projs = $conn->query("SELECT * FROM projects ORDER BY name");
                        while($p = $projs->fetch_assoc()){ echo "<option value='{$p['id']}'>{$p['name']}</option>"; }
                        ?>
                    </select>
                </div>

                <div class="input-group full-width">
                    <label>Particulars / Description</label>
                    <input type="text" name="description" class="form-control" placeholder="e.g., Downpayment for Phase 1 Land Subdividing" required>
                </div>
            </div>
            
            <button type="submit" style="background: #805AD5; color: white; border: none; padding: 15px; border-radius: 8px; font-weight: 800; font-size: 15px; width: 100%; cursor: pointer; margin-top: 10px;">
                <i class="fa-solid fa-print" style="margin-right: 8px;"></i> Save & Print Voucher
            </button>
        </form>
    </div>
</body>
</html>