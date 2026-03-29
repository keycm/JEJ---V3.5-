<?php
// pos.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    header("Location: login.php");
    exit();
}

$alert_msg = "";
$alert_type = "";

if($_SERVER['REQUEST_METHOD'] == 'POST'){
    $type = $_POST['type'];
    $category_id = $_POST['category_id'];
    $project_id = $_POST['project_id'];
    $amount = $_POST['amount'];
    $description = $_POST['description'];
    $date = $_POST['transaction_date'];
    $user_id = $_SESSION['user_id'];
    
    $or_number = generateORNumber($conn);

    $stmt = $conn->prepare("INSERT INTO transactions (or_number, transaction_date, type, category_id, project_id, amount, description, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssiidsi", $or_number, $date, $type, $category_id, $project_id, $amount, $description, $user_id);
    
    if($stmt->execute()){
        // AUDIT LOG: Recorded a transaction
        logActivity($conn, $user_id, "Processed POS Transaction", "OR: $or_number | Type: $type | Amount: ₱" . number_format($amount, 2));
        
        // Success Action: Open Voucher in new tab, then redirect back to Financials
        echo "<script>
            alert('Transaction Saved! OR Number: $or_number'); 
            window.open('voucher.php?or=$or_number', '_blank');
            window.location.href = 'financial.php';
        </script>";
        exit();
    } else {
        $alert_msg = "Error saving transaction: " . $conn->error;
        $alert_type = "error";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>POS / Enter Bills | JEJ Surveying</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@500;700;800;900&family=Open+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/modern.css">
    
    <style>
        body { background-color: #F7FAFC; display: flex; min-height: 100vh; overflow-x: hidden; }
        .sidebar { width: 260px; background: white; border-right: 1px solid #EDF2F7; display: flex; flex-direction: column; position: fixed; height: 100vh; z-index: 100; }
        .brand-box { padding: 25px; border-bottom: 1px solid #EDF2F7; display: flex; align-items: center; gap: 10px; }
        .sidebar-menu { padding: 20px 10px; flex: 1; }
        .menu-link { display: flex; align-items: center; gap: 12px; padding: 14px 20px; color: #718096; text-decoration: none; font-weight: 600; border-radius: 12px; margin-bottom: 5px; transition: all 0.2s; }
        .menu-link:hover, .menu-link.active { background: #F0FFF4; color: var(--primary); }
        .menu-link i { width: 20px; text-align: center; }
        .main-panel { margin-left: 260px; flex: 1; padding: 30px 40px; width: calc(100% - 260px); }
        
        .form-container { background: white; padding: 30px; border-radius: 16px; border: 1px solid #EDF2F7; box-shadow: var(--shadow-soft); max-width: 800px; }
        .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .input-group { margin-bottom: 15px; }
        .input-group label { display: block; font-size: 12px; font-weight: 700; color: #718096; margin-bottom: 8px; text-transform: uppercase; }
        .form-control { width: 100%; padding: 12px; border: 1px solid #E2E8F0; border-radius: 8px; background: #F9FAFB; font-family: inherit; font-size: 14px; transition: 0.2s; }
        .form-control:focus { background: white; border-color: var(--primary); outline: none; box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.1); }
        
        .btn-save { background: var(--primary); color: white; border: none; padding: 15px 25px; border-radius: 8px; font-weight: 700; cursor: pointer; width: 100%; font-size: 15px; margin-top: 10px;}
        .btn-save:hover { background: #22543D; }
    </style>
</head>
<body>

    <div class="sidebar">
        <div class="brand-box">
            <img src="assets/logo.png" style="height: 40px; width: auto; border-radius: 6px; margin-right: 10px;">
            <span style="font-size: 18px; font-weight: 800; color: var(--primary);">JEJ Admin</span>
        </div>
        
        <div class="sidebar-menu">
            <small style="padding: 0 20px; color: #A0AEC0; font-weight: 700; font-size: 11px; display: block; margin-bottom: 10px;">MAIN MENU</small>
            <a href="admin.php?view=dashboard" class="menu-link"><i class="fa-solid fa-chart-pie"></i> Dashboard</a>
            <a href="reservation.php" class="menu-link"><i class="fa-solid fa-file-signature"></i> Reservations</a>
            <a href="admin.php?view=inventory" class="menu-link"><i class="fa-solid fa-list-check"></i> Inventory</a>
            <a href="financial.php" class="menu-link active"><i class="fa-solid fa-coins"></i> Financials</a>
            
            <small style="padding: 0 20px; color: #A0AEC0; font-weight: 700; font-size: 11px; display: block; margin-top: 20px; margin-bottom: 10px;">MANAGEMENT</small>
            <a href="accounts.php" class="menu-link"><i class="fa-solid fa-users-gear"></i> Accounts</a>
            <a href="audit_logs.php" class="menu-link"><i class="fa-solid fa-clock-rotate-left"></i> Audit Logs</a>
            
            <small style="padding: 0 20px; color: #A0AEC0; font-weight: 700; font-size: 11px; display: block; margin-top: 20px; margin-bottom: 10px;">SYSTEM</small>
            <a href="index.php" class="menu-link" target="_blank"><i class="fa-solid fa-globe"></i> View Website</a>
            <a href="logout.php" class="menu-link" style="color: #E53E3E;"><i class="fa-solid fa-arrow-right-from-bracket"></i> Logout</a>
        </div>
    </div>

    <div class="main-panel">
        <div style="margin-bottom: 30px; display: flex; align-items: center; gap: 15px;">
            <a href="financial.php" style="background: white; border: 1px solid #E2E8F0; padding: 10px 15px; border-radius: 8px; color: #4A5568; text-decoration: none; font-weight: 600;"><i class="fa-solid fa-arrow-left"></i> Back</a>
            <div>
                <h1 style="font-size: 24px; font-weight: 800; color: var(--dark);">Record Transaction (POS)</h1>
                <p style="color: #718096;">Enter bills, utility payments, or manual income.</p>
            </div>
        </div>

        <?php if($alert_msg): ?>
            <div style="padding: 15px; border-radius: 10px; margin-bottom: 25px; font-weight: 600; font-size: 14px; background: #FFF5F5; color: #C53030; border: 1px solid #FED7D7;">
                <i class="fa-solid fa-exclamation-circle" style="margin-right: 8px;"></i> <?= $alert_msg ?>
            </div>
        <?php endif; ?>

        <div class="form-container">
            <form method="POST">
                <div class="form-grid">
                    <div class="input-group">
                        <label>Transaction Date</label>
                        <input type="date" name="transaction_date" class="form-control" value="<?= date('Y-m-d') ?>" required>
                    </div>
                    <div class="input-group">
                        <label>Transaction Type</label>
                        <select name="type" class="form-control" required>
                            <option value="EXPENSE">Expense / Payment (Money Out)</option>
                            <option value="INCOME">Income / Receipt (Money In)</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Category (Bills, Vouchers, etc.)</label>
                        <select name="category_id" class="form-control" required>
                            <?php
                            $cats = $conn->query("SELECT * FROM accounting_categories ORDER BY group_name, name");
                            while($c = $cats->fetch_assoc()){
                                echo "<option value='{$c['id']}'>[{$c['group_name']}] {$c['name']}</option>";
                            }
                            ?>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Project Tracker</label>
                        <select name="project_id" class="form-control" required>
                            <?php
                            $projs = $conn->query("SELECT * FROM projects ORDER BY name");
                            while($p = $projs->fetch_assoc()){
                                echo "<option value='{$p['id']}'>{$p['name']}</option>";
                            }
                            ?>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Amount (PHP)</label>
                        <input type="number" step="0.01" name="amount" class="form-control" placeholder="0.00" required>
                    </div>
                    <div class="input-group">
                        <label>Description / Notes</label>
                        <input type="text" name="description" class="form-control" placeholder="e.g., Payment for Internet Bill">
                    </div>
                </div>
                
                <button type="submit" class="btn-save"><i class="fa-solid fa-file-invoice-dollar" style="margin-right: 8px;"></i> Save Transaction & Generate Voucher</button>
            </form>
        </div>
    </div>
</body>
</html>