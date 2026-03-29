<?php
// financial.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    header("Location: login.php");
    exit();
}

$alert_msg = "";
$alert_type = "";

// --- HANDLE ADD INCOME FORM SUBMISSION ---
if(isset($_POST['add_income'])){
    $amt = floatval($_POST['amount']);
    $desc = htmlspecialchars($_POST['description']);
    $date = $_POST['trans_date'];
    
    // Generate a unique OR/Reference number if none is provided
    $or_num = !empty($_POST['or_number']) ? htmlspecialchars($_POST['or_number']) : 'INC-' . strtoupper(uniqid());
    
    if($amt > 0){
        // BUG FIX: Check if the OR Number already exists in the database to prevent Fatal Error 1062
        $check_stmt = $conn->prepare("SELECT id FROM transactions WHERE or_number = ?");
        $check_stmt->bind_param("s", $or_num);
        $check_stmt->execute();
        $check_res = $check_stmt->get_result();

        if($check_res->num_rows > 0) {
            // Duplicate found! Show a friendly warning instead of a fatal error.
            $alert_msg = "Error: The OR / Reference Number '<b>$or_num</b>' is already in use. Please enter a different number.";
            $alert_type = "error";
        } else {
            // No duplicate, safe to insert
            $stmt = $conn->prepare("INSERT INTO transactions (type, amount, transaction_date, description, or_number) VALUES ('INCOME', ?, ?, ?, ?)");
            $stmt->bind_param("dsss", $amt, $date, $desc, $or_num);
            
            try {
                if($stmt->execute()) {
                    $alert_msg = "Income of ₱" . number_format($amt, 2) . " successfully recorded!";
                    $alert_type = "success";
                } else {
                    $alert_msg = "Failed to record income. Please try again.";
                    $alert_type = "error";
                }
            } catch (mysqli_sql_exception $e) {
                // Failsafe catch for any other SQL constraints
                $alert_msg = "Database Error: Please ensure all data is valid and unique.";
                $alert_type = "error";
            }
        }
    } else {
        $alert_msg = "Amount must be greater than zero.";
        $alert_type = "error";
    }
}


// --- DATA FETCHING (FINANCIAL & ACCOUNTING) ---
$total_in = 0; $total_out = 0; $current_balance = 0;
$low_fund_threshold = 20000;
$chart_dates = []; $chart_totals = [];
$calendar_events = [];
$check_vouchers = [];

$checkTable = $conn->query("SHOW TABLES LIKE 'transactions'");
if($checkTable && $checkTable->num_rows > 0) {
    // 1. Calculate Balances
    $fundQuery = $conn->query("SELECT 
        SUM(CASE WHEN type='INCOME' THEN amount ELSE 0 END) as total_in,
        SUM(CASE WHEN type='EXPENSE' THEN amount ELSE 0 END) as total_out
        FROM transactions");
    if($funds = $fundQuery->fetch_assoc()){
        $total_in = $funds['total_in'] ?? 0;
        $total_out = $funds['total_out'] ?? 0;
        $current_balance = $total_in - $total_out;
    }

    // 2. Fetch Chart Data (Filtered)
    $filter = $_GET['filter'] ?? 'weekly';
    
    if ($filter == 'yearly') {
        // Group by Month for the current year
        $chartData = $conn->query("SELECT DATE_FORMAT(transaction_date, '%b %Y') as label, SUM(amount) as total FROM transactions WHERE type='EXPENSE' AND YEAR(transaction_date) = YEAR(CURRENT_DATE()) GROUP BY label ORDER BY MIN(transaction_date) ASC");
        while($row = $chartData->fetch_assoc()){
            $chart_dates[] = $row['label'];
            $chart_totals[] = $row['total'];
        }
        $chart_title = "Expense Trends (This Year)";
    } 
    elseif ($filter == 'monthly') {
        // Group by Day for the current month
        $chartData = $conn->query("SELECT DATE_FORMAT(transaction_date, '%b %d') as label, SUM(amount) as total FROM transactions WHERE type='EXPENSE' AND MONTH(transaction_date) = MONTH(CURRENT_DATE()) AND YEAR(transaction_date) = YEAR(CURRENT_DATE()) GROUP BY transaction_date ORDER BY transaction_date ASC");
        while($row = $chartData->fetch_assoc()){
            $chart_dates[] = $row['label'];
            $chart_totals[] = $row['total'];
        }
        $chart_title = "Expense Trends (This Month)";
    } 
    else { 
        // Default: Weekly (Last 7 Days)
        $chartData = $conn->query("SELECT DATE_FORMAT(transaction_date, '%b %d') as label, SUM(amount) as total FROM transactions WHERE type='EXPENSE' GROUP BY transaction_date ORDER BY transaction_date DESC LIMIT 7");
        while($row = $chartData->fetch_assoc()){
            $chart_dates[] = $row['label'];
            $chart_totals[] = $row['total'];
        }
        $chart_dates = array_reverse($chart_dates);
        $chart_totals = array_reverse($chart_totals);
        $chart_title = "Expense Trends (Last 7 Days)";
    }

    // 3. Fetch Calendar Events
    $ev = $conn->query("SELECT * FROM transactions");
    while($row = $ev->fetch_assoc()){
        // Vibrant Semantic Colors for Calendar (Emerald for Income, Red for Expense)
        $color = ($row['type'] == 'INCOME') ? '#10b981' : '#ef4444';
        $calendar_events[] = [
            'title' => $row['type'] . ': ₱' . number_format($row['amount'], 0),
            'start' => $row['transaction_date'],
            'color' => $color
        ];
    }

    // 4. Fetch Recent Check Vouchers
    $colCheck = $conn->query("SHOW COLUMNS FROM transactions LIKE 'is_check'");
    if($colCheck && $colCheck->num_rows > 0) {
        $cv_query = $conn->query("SELECT t.*, c.name as category FROM transactions t LEFT JOIN accounting_categories c ON t.category_id = c.id WHERE t.is_check = 1 ORDER BY t.transaction_date DESC, t.id DESC LIMIT 10");
        if($cv_query) {
            while($row = $cv_query->fetch_assoc()){
                $check_vouchers[] = $row;
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Financial Dashboard | JEJ Surveying</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/fullcalendar@6.1.11/index.global.min.js"></script>

    <style>
        :root {
            /* NATURE GREEN THEME (Primary Structure) */
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

        /* Sidebar Styling */
        .sidebar { width: 260px; background: #ffffff; border-right: 1px solid var(--gray-border); display: flex; flex-direction: column; position: fixed; height: 100vh; z-index: 100; box-shadow: var(--shadow-sm); }
        .brand-box { padding: 25px; border-bottom: 1px solid var(--gray-border); display: flex; align-items: center; gap: 12px; }
        .sidebar-menu { padding: 20px 15px; flex: 1; overflow-y: auto; }
        .menu-link { display: flex; align-items: center; gap: 12px; padding: 12px 18px; color: #455a64; text-decoration: none; font-weight: 500; font-size: 14px; border-radius: 10px; margin-bottom: 6px; transition: all 0.2s ease; }
        .menu-link:hover { background: var(--gray-light); color: var(--primary); }
        .menu-link.active { background: var(--primary-light); color: var(--primary); font-weight: 600; border-left: 4px solid var(--primary); }
        .menu-link i { width: 20px; text-align: center; font-size: 16px; opacity: 0.8; }
        
        /* Main Panel & Header */
        .main-panel { margin-left: 260px; flex: 1; padding: 0; width: calc(100% - 260px); display: flex; flex-direction: column; }
        
        .top-header { display: flex; justify-content: space-between; align-items: center; background: #ffffff; padding: 20px 40px; border-bottom: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); z-index: 50; }
        .header-title h1 { font-size: 22px; font-weight: 800; color: var(--dark); margin: 0 0 4px 0; letter-spacing: -0.5px;}
        .header-title p { color: var(--text-muted); font-size: 13px; margin: 0; }

        /* Profile Dropdown */
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

        /* Stats Grid - Vibrant Semantic Colors */
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 24px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); position: relative; overflow: hidden; transition: transform 0.2s;}
        .stat-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
        .stat-card h2 { font-size: 32px; font-weight: 800; margin: 5px 0 0; letter-spacing: -1px;}
        .stat-card small { font-size: 12px; font-weight: 700; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.5px; }
        .stat-icon { position: absolute; right: -15px; bottom: -15px; font-size: 90px; opacity: 0.08; transform: rotate(-15deg); transition: transform 0.3s;}
        .stat-card:hover .stat-icon { transform: rotate(0deg) scale(1.1); }
        
        .sc-income { border-top: 4px solid #10b981; } /* Emerald */
        .sc-expense { border-top: 4px solid #ef4444; } /* Red */
        .sc-balance { border-top: 4px solid #3b82f6; } /* Blue */
        
        /* Dashboard Widgets */
        .dashboard-widgets { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 30px; }
        @media (max-width: 1100px) { .dashboard-widgets { grid-template-columns: 1fr; } }
        
        .widget-card { background: white; padding: 25px; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); display: flex; flex-direction: column; height: 450px;}
        .widget-title { font-size: 16px; font-weight: 800; color: #1e293b; margin-bottom: 20px; border-bottom: 1px solid var(--gray-border); padding-bottom: 15px; display: flex; justify-content: space-between; align-items: center;}
        
        /* Filter Select styling */
        .chart-filter { padding: 6px 12px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 12px; font-weight: 600; color: #475569; outline: none; cursor: pointer; transition: 0.2s;}
        .chart-filter:focus { border-color: var(--primary); box-shadow: 0 0 0 2px rgba(46, 125, 50, 0.15); }

        /* Action Buttons - Vibrant Semantic Colors */
        .btn-action { padding: 10px 18px; border-radius: 8px; font-size: 13px; font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; cursor: pointer; border: none; transition: 0.2s; color: white; box-shadow: var(--shadow-sm);}
        
        .btn-add-income { background: #10b981; } /* Emerald */
        .btn-add-income:hover { background: #059669; transform: translateY(-1px); } 

        .btn-issue-check { background: #8b5cf6; } /* Violet */
        .btn-issue-check:hover { background: #7c3aed; transform: translateY(-1px); } 
        
        .btn-enter-bills { background: #f59e0b; } /* Amber for Bills */
        .btn-enter-bills:hover { background: #d97706; transform: translateY(-1px); } 
        
        .btn-export { background: #64748b; } /* Slate */
        .btn-export:hover { background: #475569; transform: translateY(-1px); }

        /* Print Button - Sky Blue */
        .btn-print { background: #e0f2fe; color: #0284c7; border: 1px solid #bae6fd; padding: 6px 14px; border-radius: 6px; font-size: 12px; font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; gap: 5px; transition: 0.2s;}
        .btn-print:hover { background: #bae6fd; color: #0369a1; }

        /* Table Styling */
        .table-container { background: white; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); overflow: hidden; margin-bottom: 30px; }
        .table-header { padding: 20px 24px; border-bottom: 1px solid var(--gray-border); display: flex; justify-content: space-between; align-items: center; background: #fff;}
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px 24px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; background: var(--gray-light); border-bottom: 1px solid var(--gray-border); letter-spacing: 0.5px;}
        td { padding: 16px 24px; border-bottom: 1px solid var(--gray-border); color: #37474f; font-size: 14px; vertical-align: middle; }
        tr:hover td { background: #fdfdfd; }
        tr:last-child td { border-bottom: none; }

        /* Calendar tweaks - Fixed Layout to prevent overflow */
        .calendar-wrapper { flex: 1; min-height: 0; width: 100%; }
        .fc .fc-toolbar-title { font-size: 14px !important; color: var(--dark); font-weight: 700;}
        .fc .fc-button { padding: 4px 10px !important; font-size: 12px !important; background: var(--primary) !important; border: none !important; border-radius: 6px !important;}
        .fc .fc-day-today { background: var(--gray-light) !important; }
        .fc-event { font-size: 11px !important; padding: 3px 5px !important; border: none !important; border-radius: 4px !important; font-weight: 600; cursor: pointer; color: white !important;}

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
            <a href="financial.php" class="menu-link active"><i class="fa-solid fa-coins"></i> Financials</a>
            <a href="transaction_history.php" class="menu-link" style="padding-left: 35px; font-size: 13px;"><i class="fa-solid fa-list-ul" style="font-size: 12px;"></i> Ledger List</a>
            <a href="payment_tracking.php" class="menu-link"><i class="fa-solid fa-file-invoice-dollar"></i> Payment Tracking</a>
            
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
                <h1>Financial Dashboard</h1>
                <p>Track income, expenses, vouchers, and project accounting.</p>
            </div>
            
            <div style="display: flex; gap: 10px; flex-wrap:wrap; margin-right: 20px;">
                <button onclick="openModal('incomeModal')" class="btn-action btn-add-income"><i class="fa-solid fa-plus-circle"></i> Add Income</button>
                <a href="pos.php" class="btn-action btn-enter-bills"><i class="fa-solid fa-cash-register"></i> Enter Bills</a>
                <a href="issue_check.php" class="btn-action btn-issue-check"><i class="fa-solid fa-money-check"></i> Check Voucher</a>
                <a href="export_excel.php" class="btn-action btn-export"><i class="fa-solid fa-file-excel"></i> Export Finance</a>
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
                <div style="padding: 16px 20px; border-radius: 10px; margin-bottom: 25px; font-weight: 500; font-size: 14px; background: <?= $alert_type=='success' ? '#e8f5e9' : '#fbe9e7' ?>; color: <?= $alert_type=='success' ? '#2e7d32' : '#d84315' ?>; border: 1px solid <?= $alert_type=='success' ? '#c8e6c9' : '#ffccbc' ?>; box-shadow: var(--shadow-sm);">
                    <i class="fa-solid <?= $alert_type=='success'?'fa-check-circle':'fa-exclamation-circle' ?>" style="margin-right: 10px;"></i>
                    <?= $alert_msg ?>
                </div>
            <?php endif; ?>

            <?php if($current_balance < $low_fund_threshold): ?>
            <div style="background: #fef2f2; border-left: 5px solid #ef4444; padding: 20px; border-radius: 8px; margin-bottom: 30px; display: flex; align-items: center; gap: 15px; box-shadow: var(--shadow-sm);">
                <i class="fa-solid fa-triangle-exclamation" style="color: #ef4444; font-size: 24px;"></i>
                <div>
                    <strong style="color: #b91c1c; font-size: 15px; display: block; margin-bottom: 4px;">LOW FUND WARNING</strong>
                    <span style="color: #dc2626; font-size: 13px;">Current Balance is <b>₱<?= number_format($current_balance, 2) ?></b>, which is below the safe threshold of ₱<?= number_format($low_fund_threshold) ?>.</span>
                </div>
            </div>
            <?php endif; ?>

            <div class="stats-grid">
                <div class="stat-card sc-income">
                    <small>Total Income (Collected)</small>
                    <h2 style="color: #059669;">₱<?= number_format($total_in, 2) ?></h2>
                    <i class="fa-solid fa-arrow-trend-up stat-icon" style="color: #10b981;"></i>
                </div>
                <div class="stat-card sc-expense">
                    <small>Total Expenses (Bills/Checks)</small>
                    <h2 style="color: #dc2626;">₱<?= number_format($total_out, 2) ?></h2>
                    <i class="fa-solid fa-arrow-trend-down stat-icon" style="color: #ef4444;"></i>
                </div>
                <div class="stat-card sc-balance">
                    <small>Current Remaining Balance</small>
                    <h2 style="color: #2563eb;">₱<?= number_format($current_balance, 2) ?></h2>
                    <i class="fa-solid fa-wallet stat-icon" style="color: #3b82f6;"></i>
                </div>
            </div>

            <div class="dashboard-widgets">
                <div class="widget-card">
                    <div class="widget-title">
                        <span><i class="fa-solid fa-chart-line" style="color: #ef4444; margin-right: 8px;"></i> <?= $chart_title ?></span>
                        <select class="chart-filter" onchange="window.location.href='financial.php?filter='+this.value">
                            <option value="weekly" <?= $filter=='weekly'?'selected':'' ?>>Last 7 Days</option>
                            <option value="monthly" <?= $filter=='monthly'?'selected':'' ?>>This Month</option>
                            <option value="yearly" <?= $filter=='yearly'?'selected':'' ?>>This Year</option>
                        </select>
                    </div>
                    <div style="position: relative; height: 350px; width: 100%;">
                        <canvas id="expenseChart"></canvas>
                    </div>
                </div>

                <div class="widget-card">
                    <div class="widget-title">
                        <span><i class="fa-solid fa-calendar-days" style="color: #3b82f6; margin-right: 8px;"></i> Financial Tracker</span>
                    </div>
                    <div id="calendar" style="height: 380px;"></div>
                </div>
            </div>

            <div class="table-container">
                <div class="table-header">
                    <h3 style="margin: 0; font-size: 16px; font-weight: 800; color: #1e293b;"><i class="fa-solid fa-money-check" style="color: #8b5cf6; margin-right: 8px;"></i> Recent Check Vouchers</h3>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>CV Number</th>
                            <th>Payee</th>
                            <th>Bank & Check No</th>
                            <th>Particulars</th>
                            <th>Amount</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if(!empty($check_vouchers)): ?>
                            <?php foreach($check_vouchers as $cv): ?>
                            <tr>
                                <td style="font-weight: 600; color: #64748b; font-size: 13px;"><?= date('M d, Y', strtotime($cv['transaction_date'])) ?></td>
                                <td><strong style="color: #7c3aed;"><?= $cv['or_number'] ?></strong></td>
                                <td style="font-weight: 700; color: #1e293b;"><?= htmlspecialchars($cv['payee']) ?></td>
                                <td>
                                    <div style="font-size: 13px; font-weight: 700; color: #334155;"><?= htmlspecialchars($cv['bank_name']) ?></div>
                                    <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">Check #: <?= htmlspecialchars($cv['check_number']) ?></div>
                                </td>
                                <td style="font-size: 12px; color: #475569; max-width: 250px;"><?= htmlspecialchars($cv['description']) ?></td>
                                <td style="font-weight: 700; color: #ef4444; font-size: 15px;">₱<?= number_format($cv['amount'], 2) ?></td>
                                <td>
                                    <a href="print_check_voucher.php?cv=<?= $cv['or_number'] ?>" target="_blank" class="btn-print">
                                        <i class="fa-solid fa-print"></i> Print
                                    </a>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr><td colspan="7" style="text-align: center; padding: 40px; color: #94a3b8;"><i class="fa-solid fa-folder-open" style="font-size: 30px; margin-bottom: 10px; display: block; color: #cbd5e1;"></i>No Check Vouchers recorded yet.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
        </div>
    </div>

    <div id="incomeModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fa-solid fa-plus-circle" style="color: #10b981; margin-right: 5px;"></i> Add Income</h2>
                <button type="button" class="close-btn" onclick="closeModal('incomeModal')"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <form method="POST" style="padding: 25px;">
                <div class="form-group">
                    <label>Amount (₱)</label>
                    <input type="number" step="0.01" name="amount" class="form-control" placeholder="0.00" required>
                </div>
                <div class="form-group">
                    <label>Date Received</label>
                    <input type="date" name="trans_date" class="form-control" value="<?= date('Y-m-d') ?>" required>
                </div>
                <div class="form-group">
                    <label>OR / Reference Number (Optional)</label>
                    <input type="text" name="or_number" class="form-control" placeholder="E.g., OR-12345 or Leave blank to auto-generate">
                </div>
                <div class="form-group">
                    <label>Description / Particulars</label>
                    <textarea name="description" class="form-control" rows="3" placeholder="E.g., Bank Interest, Miscellaneous Cash..." required></textarea>
                </div>
                
                <div style="margin-top: 25px; text-align: right; border-top: 1px solid var(--gray-border); padding-top: 15px;">
                    <button type="button" onclick="closeModal('incomeModal')" style="background:#f1f5f9; color:#475569; border: 1px solid #cbd5e1; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer; margin-right: 10px;">Cancel</button>
                    <button type="submit" name="add_income" style="background:#10b981; color:white; border: none; padding: 10px 24px; border-radius: 8px; font-weight: 600; cursor: pointer;"><i class="fa-solid fa-save"></i> Save Income</button>
                </div>
            </form>
        </div>
    </div>

    <script>
    // Modal Functions
    function openModal(id) {
        document.getElementById(id).style.display = 'flex';
    }
    function closeModal(id) {
        document.getElementById(id).style.display = 'none';
    }
    window.onclick = function(event) {
        let m = document.getElementById('incomeModal');
        if (event.target === m) closeModal('incomeModal');
    }

    document.addEventListener('DOMContentLoaded', function() {
        const formatCurrency = (val) => new Intl.NumberFormat('en-PH', { style: 'currency', currency: 'PHP', minimumFractionDigits: 0 }).format(val);

        // Chart Initialization
        const ctx = document.getElementById('expenseChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: <?= json_encode($chart_dates) ?>,
                datasets: [{
                    label: 'Filtered Expenses',
                    data: <?= json_encode($chart_totals) ?>,
                    backgroundColor: 'rgba(239, 68, 68, 0.85)', // Vibrant Red
                    hoverBackgroundColor: 'rgba(220, 38, 38, 1)',
                    borderRadius: 6,
                    barThickness: 25
                }]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: { 
                    legend: { display: false },
                    tooltip: {
                        callbacks: { label: function(context) { return ' Total: ' + formatCurrency(context.raw); } }
                    } 
                }, 
                scales: { 
                    y: { 
                        beginAtZero: true, 
                        grid: { color: '#e2e8f0' }, 
                        border: { display: false },
                        ticks: { font: {family: 'Inter', size: 10}, color: '#94a3b8', callback: function(value) { 
                            if(value >= 1000000) return '₱' + (value/1000000).toFixed(1) + 'M';
                            if(value >= 1000) return '₱' + (value/1000).toFixed(1) + 'K';
                            return '₱' + value; 
                        } }
                    }, 
                    x: { 
                        grid: { display: false },
                        ticks: { font: {family: 'Inter', size: 11}, color: '#64748b' }
                    } 
                } 
            }
        });

        // Calendar Initialization (Using explicit height to prevent flex overflow bug)
        var calendarEl = document.getElementById('calendar');
        var calendar = new FullCalendar.Calendar(calendarEl, {
            initialView: 'dayGridMonth', 
            height: 380, // Explicit height solves the UI squishing/overflow bug
            headerToolbar: { left: 'prev,next', center: 'title', right: 'today' },
            events: <?= json_encode($calendar_events) ?>, 
            eventTimeFormat: { hour: 'numeric', minute: '2-digit', meridiem: 'short' },
            themeSystem: 'standard',
            eventMouseEnter: function(info) {
                info.el.style.transform = 'scale(1.02)';
                info.el.style.transition = 'all 0.2s';
            },
            eventMouseLeave: function(info) {
                info.el.style.transform = 'scale(1)';
            }
        });
        calendar.render();
    });
    </script>
</body>
</html>