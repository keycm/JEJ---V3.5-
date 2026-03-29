<?php
// payment_terms.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    header("Location: login.php");
    exit();
}

if(!isset($_GET['res_id'])){
    header("Location: reservation.php");
    exit();
}

$res_id = (int)$_GET['res_id'];
$alert_msg = "";
$alert_type = "";

// Handle Form Submission
if(isset($_POST['save_terms'])){
    $type = $_POST['payment_type'];
    
    // If CASH, zero out installment details
    $months = ($type === 'INSTALLMENT') ? (int)$_POST['installment_months'] : 0;
    $monthly = ($type === 'INSTALLMENT') ? (float)$_POST['monthly_payment'] : 0.00;

    $stmt = $conn->prepare("UPDATE reservations SET payment_type=?, installment_months=?, monthly_payment=? WHERE id=?");
    $stmt->bind_param("sidi", $type, $months, $monthly, $res_id);
    
    if($stmt->execute()){
        $alert_msg = "Payment terms have been successfully updated!";
        $alert_type = "success";
        
        // Log Activity if function exists in config
        if (function_exists('logActivity')) {
            logActivity($conn, $_SESSION['user_id'], "Updated Payment Terms", "Res ID: $res_id | Term: $type");
        }
    } else {
        $alert_msg = "Failed to update payment terms.";
        $alert_type = "error";
    }
}

// Fetch Full Reservation Data
$stmt = $conn->prepare("
    SELECT r.*, u.fullname, u.phone, u.email, l.block_no, l.lot_no, l.total_price, l.area, l.property_type, l.location 
    FROM reservations r 
    JOIN users u ON r.user_id = u.id 
    JOIN lots l ON r.lot_id = l.id 
    WHERE r.id = ?
");
$stmt->bind_param("i", $res_id);
$stmt->execute();
$resData = $stmt->get_result()->fetch_assoc();

if(!$resData) { die("Reservation not found in the system."); }

$total_price = (float)$resData['total_price'];
$default_dp = $total_price * 0.20; // 20% Base Calculation
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configure Payment Terms | JEJ Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary: #2e7d32;
            --primary-dark: #1b5e20;
            --primary-light: #e8f5e9;
            --gray-bg: #f4f7f6;
            --border: #e2e8f0;
            --text-main: #2d3748;
            --text-muted: #718096;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
        }

        body { 
            background-color: var(--gray-bg); 
            font-family: 'Inter', sans-serif; 
            color: var(--text-main); 
            margin: 0; 
            padding: 40px 20px; 
            display: flex;
            justify-content: center;
        }

        .container {
            max-width: 1000px;
            width: 100%;
        }

        .header-actions {
            margin-bottom: 25px;
            display: flex;
            align-items: center;
        }

        .btn-back {
            color: var(--text-muted);
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: color 0.2s;
        }

        .btn-back:hover {
            color: var(--primary-dark);
        }

        .alert {
            padding: 16px 20px;
            border-radius: 10px;
            margin-bottom: 25px;
            font-weight: 500;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .alert.success { background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; }
        .alert.error { background: #fee2e2; color: #dc2626; border: 1px solid #fecaca; }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1.2fr;
            gap: 25px;
        }

        @media (max-width: 768px) {
            .dashboard-grid { grid-template-columns: 1fr; }
        }

        .card {
            background: #ffffff;
            border-radius: 16px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
            overflow: hidden;
        }

        .card-header {
            padding: 20px 25px;
            border-bottom: 1px solid var(--border);
            background: #fafbfc;
        }

        .card-header h2 {
            margin: 0;
            font-size: 18px;
            font-weight: 700;
            color: var(--primary-dark);
        }

        .card-body {
            padding: 25px;
        }

        /* Summary Info Box */
        .info-row { display: flex; justify-content: space-between; margin-bottom: 12px; font-size: 14px; }
        .info-row span:first-child { color: var(--text-muted); font-weight: 500; }
        .info-row span:last-child { font-weight: 600; color: var(--text-main); text-align: right; }

        .price-box {
            background: var(--primary-dark);
            color: white;
            padding: 20px;
            border-radius: 12px;
            margin-top: 20px;
            text-align: center;
        }
        .price-box small { display: block; font-size: 13px; opacity: 0.8; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 5px; }
        .price-box .amount { font-size: 32px; font-weight: 800; }

        /* Form Styles */
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; font-size: 13px; font-weight: 600; color: #4a5568; margin-bottom: 8px; }
        .form-control { 
            width: 100%; 
            padding: 12px 16px; 
            border: 1px solid #cbd5e1; 
            border-radius: 8px; 
            font-family: inherit; 
            font-size: 14px; 
            box-sizing: border-box;
            transition: all 0.2s;
        }
        .form-control:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.1); }
        select.form-control { cursor: pointer; }

        .calculator-box {
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .balance-display {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: #fff;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-top: 15px;
        }
        .balance-display span:first-child { font-size: 13px; font-weight: 600; color: var(--text-muted); }
        .balance-display span:last-child { font-size: 18px; font-weight: 800; color: #e11d48; }

        .btn-submit {
            background: var(--primary);
            color: white;
            border: none;
            width: 100%;
            padding: 15px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 15px;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 4px 6px rgba(46, 125, 50, 0.2);
        }
        .btn-submit:hover { background: var(--primary-dark); transform: translateY(-1px); box-shadow: 0 6px 12px rgba(46, 125, 50, 0.3); }

    </style>
</head>
<body>

    <div class="container">
        <div class="header-actions">
            <a href="reservation.php" class="btn-back"><i class="fa-solid fa-arrow-left"></i> Return to Reservations</a>
        </div>

        <?php if($alert_msg): ?>
            <div class="alert <?= $alert_type ?>">
                <i class="fa-solid <?= $alert_type == 'success' ? 'fa-check-circle' : 'fa-circle-exclamation' ?>"></i>
                <?= $alert_msg ?>
            </div>
        <?php endif; ?>

        <div class="dashboard-grid">
            
            <div class="card">
                <div class="card-header">
                    <h2><i class="fa-solid fa-file-invoice" style="margin-right: 8px;"></i> Reservation Overview</h2>
                </div>
                <div class="card-body">
                    <h3 style="font-size: 14px; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border); padding-bottom: 8px; margin: 0 0 15px;">Buyer Details</h3>
                    <div class="info-row"><span>Full Name:</span> <span><?= htmlspecialchars($resData['fullname']) ?></span></div>
                    <div class="info-row"><span>Contact:</span> <span><?= htmlspecialchars($resData['phone'] ?? 'N/A') ?></span></div>
                    <div class="info-row"><span>Email:</span> <span><?= htmlspecialchars($resData['email'] ?? 'N/A') ?></span></div>

                    <h3 style="font-size: 14px; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border); padding-bottom: 8px; margin: 25px 0 15px;">Property Details</h3>
                    <div class="info-row"><span>Property Type:</span> <span><?= htmlspecialchars($resData['property_type']) ?></span></div>
                    <div class="info-row"><span>Location:</span> <span><?= htmlspecialchars($resData['location']) ?></span></div>
                    <div class="info-row"><span>Block & Lot:</span> <span style="color: var(--primary); font-weight: 800;">Block <?= htmlspecialchars($resData['block_no']) ?>, Lot <?= htmlspecialchars($resData['lot_no']) ?></span></div>
                    <div class="info-row"><span>Lot Area:</span> <span><?= number_format($resData['area'], 2) ?> m²</span></div>

                    <div class="price-box">
                        <small>Total Contract Price</small>
                        <div class="amount">₱<?= number_format($total_price, 2) ?></div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2><i class="fa-solid fa-sliders" style="margin-right: 8px;"></i> Configure Payment Terms</h2>
                </div>
                <div class="card-body">
                    <form method="POST">
                        
                        <div class="form-group">
                            <label>Payment Mode / Type</label>
                            <select name="payment_type" id="payment_type" class="form-control" onchange="toggleCalculator()" required>
                                <option value="" disabled selected>Select Payment Plan...</option>
                                <option value="CASH" <?= $resData['payment_type'] == 'CASH' ? 'selected' : '' ?>>Spot Cash (Full Payment)</option>
                                <option value="INSTALLMENT" <?= $resData['payment_type'] == 'INSTALLMENT' ? 'selected' : '' ?>>Installment (Downpayment + Monthly)</option>
                            </select>
                        </div>

                        <div id="installment_setup" style="display: <?= $resData['payment_type'] == 'INSTALLMENT' ? 'block' : 'none' ?>;">
                            
                            <div class="calculator-box">
                                <div class="form-group">
                                    <label>Down Payment Amount (₱)</label>
                                    <input type="number" step="0.01" id="dp_amount" class="form-control" value="<?= $default_dp ?>" oninput="calculateAmortization()">
                                    <small style="color: var(--text-muted); font-size: 12px; margin-top: 5px; display: block;">Default is 20%. Adjust to exact cash tendered.</small>
                                </div>

                                <div class="balance-display">
                                    <span>Remaining Balance to Finance</span>
                                    <span id="remaining_balance">₱0.00</span>
                                </div>
                            </div>

                            <div class="dashboard-grid" style="gap: 15px; grid-template-columns: 1fr 1fr;">
                                <div class="form-group">
                                    <label>Term Length (Months)</label>
                                    <select name="installment_months" id="installment_months" class="form-control" onchange="calculateAmortization()">
                                        <?php 
                                        $terms = [6, 12, 18, 24, 36, 48, 60];
                                        foreach($terms as $t){
                                            $sel = ($resData['installment_months'] == $t) ? 'selected' : '';
                                            echo "<option value='$t' $sel>$t Months</option>";
                                        }
                                        ?>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <label>Monthly Amortization (₱)</label>
                                    <input type="number" step="0.01" name="monthly_payment" id="monthly_payment" class="form-control" value="<?= $resData['monthly_payment'] ?>" style="background: #eef2f6; font-weight: 700; color: var(--primary-dark);" readonly>
                                </div>
                            </div>

                        </div>

                        <button type="submit" name="save_terms" class="btn-submit">
                            <i class="fa-solid fa-floppy-disk" style="margin-right: 6px;"></i> Save & Finalize Terms
                        </button>

                    </form>
                </div>
            </div>

        </div>
    </div>

    <script>
        const TCP = <?= $total_price ?>;

        function toggleCalculator() {
            const type = document.getElementById('payment_type').value;
            const installmentSetup = document.getElementById('installment_setup');
            
            if (type === 'INSTALLMENT') {
                installmentSetup.style.display = 'block';
                calculateAmortization();
            } else {
                installmentSetup.style.display = 'none';
                document.getElementById('monthly_payment').value = 0;
            }
        }

        function calculateAmortization() {
            let dpInput = document.getElementById('dp_amount').value;
            let dpAmount = parseFloat(dpInput) || 0;
            
            // Prevent DP from exceeding Total Contract Price
            if (dpAmount > TCP) {
                dpAmount = TCP;
                document.getElementById('dp_amount').value = dpAmount;
            }

            // Calculate Balance
            let balance = TCP - dpAmount;
            if (balance < 0) balance = 0;

            document.getElementById('remaining_balance').innerText = '₱ ' + balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
            
            // Calculate Monthly
            let months = parseInt(document.getElementById('installment_months').value) || 12;
            let monthly = (balance > 0 && months > 0) ? (balance / months) : 0;
            
            document.getElementById('monthly_payment').value = monthly.toFixed(2);
        }

        // Initialize calculations on page load if Installment is selected
        document.addEventListener('DOMContentLoaded', () => {
            if (document.getElementById('payment_type').value === 'INSTALLMENT') {
                // Only run default calculation if there isn't already a saved monthly payment, 
                // OR run it to ensure the balance text is correct.
                calculateAmortization();
            }
        });
    </script>
</body>
</html>