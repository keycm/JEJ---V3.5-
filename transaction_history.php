<?php
// transaction_history.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    header("Location: login.php");
    exit();
}

// --- FILTERING LOGIC ---
$where_clauses = ["1=1"];
$params = [];
$types = "";

// 1. Filter by Type (Income, Expense, Check Voucher)
$filter_type = $_GET['type'] ?? 'ALL';
if ($filter_type == 'INCOME') {
    $where_clauses[] = "t.type = 'INCOME'";
} elseif ($filter_type == 'EXPENSE') {
    $where_clauses[] = "t.type = 'EXPENSE' AND (t.is_check = 0 OR t.is_check IS NULL)";
} elseif ($filter_type == 'CHECK') {
    $where_clauses[] = "t.is_check = 1";
}

// 2. Filter by Date Range
$start_date = $_GET['start_date'] ?? '';
$end_date = $_GET['end_date'] ?? '';

if (!empty($start_date)) {
    $where_clauses[] = "t.transaction_date >= ?";
    $params[] = $start_date;
    $types .= "s";
}
if (!empty($end_date)) {
    $where_clauses[] = "t.transaction_date <= ?";
    $params[] = $end_date;
    $types .= "s";
}

// 3. Search Query (Description, OR Number, Payee)
$search = $_GET['search'] ?? '';
if (!empty($search)) {
    $search_param = "%" . $search . "%";
    $where_clauses[] = "(t.description LIKE ? OR t.or_number LIKE ? OR t.payee LIKE ?)";
    $params[] = $search_param;
    $params[] = $search_param;
    $params[] = $search_param;
    $types .= "sss";
}

$where_sql = implode(" AND ", $where_clauses);

// Build and Execute Query
$query = "SELECT t.*, c.name as category_name 
          FROM transactions t 
          LEFT JOIN accounting_categories c ON t.category_id = c.id 
          WHERE $where_sql 
          ORDER BY t.transaction_date DESC, t.id DESC";

$stmt = $conn->prepare($query);
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();

// Calculate totals for the current view
$total_income_view = 0;
$total_expense_view = 0;
$transactions = [];

while($row = $result->fetch_assoc()){
    $transactions[] = $row;
    if($row['type'] == 'INCOME') {
        $total_income_view += $row['amount'];
    } else {
        $total_expense_view += $row['amount'];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Transaction History | JEJ Surveying</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
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

        /* Toolbar / Filters */
        .toolbar { background: white; padding: 20px; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); margin-bottom: 25px; display: flex; flex-wrap: wrap; gap: 15px; align-items: center; justify-content: space-between;}
        .filter-group { display: flex; gap: 10px; align-items: center; flex-wrap: wrap;}
        .form-control { padding: 9px 14px; border: 1px solid #cbd5e1; border-radius: 8px; font-family: inherit; font-size: 13px; outline: none; transition: 0.2s; color: #475569;}
        .form-control:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.15); }
        
        .btn-filter { background: var(--primary); color: white; border: none; padding: 9px 18px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 6px;}
        .btn-filter:hover { background: var(--dark); box-shadow: 0 4px 6px rgba(46, 125, 50, 0.2); }
        .btn-reset { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; padding: 9px 18px; border-radius: 8px; font-weight: 600; cursor: pointer; text-decoration: none; transition: 0.2s;}
        .btn-reset:hover { background: #e2e8f0; }

        /* Summary Cards */
        .summary-wrapper { display: flex; gap: 20px; margin-bottom: 25px; }
        .summary-card { flex: 1; background: white; padding: 15px 20px; border-radius: 12px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); display: flex; align-items: center; gap: 15px;}
        .summary-icon { width: 45px; height: 45px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 20px; }
        .si-inc { background: #d1fae5; color: #059669; }
        .si-exp { background: #fee2e2; color: #dc2626; }
        
        /* Table Styling */
        .table-container { background: white; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); overflow: hidden; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px 24px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; background: var(--gray-light); border-bottom: 1px solid var(--gray-border); letter-spacing: 0.5px;}
        td { padding: 16px 24px; border-bottom: 1px solid var(--gray-border); color: #37474f; font-size: 13px; vertical-align: middle; }
        tr:hover td { background: #fdfdfd; }
        tr:last-child td { border-bottom: none; }

        /* Badges */
        .badge { padding: 5px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; letter-spacing: 0.3px; display: inline-block;}
        .b-inc { background: #d1fae5; color: #059669; } /* Emerald */
        .b-exp { background: #fef3c7; color: #d97706; } /* Amber */
        .b-chk { background: #ede9fe; color: #7c3aed; } /* Violet */

        .amount-pos { color: #10b981; font-weight: 700; }
        .amount-neg { color: #ef4444; font-weight: 700; }
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
        </div>
    </div>

    <div class="main-panel">
        
        <div class="top-header">
            <div class="header-title">
                <h1>Financial Ledger & Transactions</h1>
                <p>Complete history of all income, bills, and vouchers.</p>
            </div>
            
            <div style="display: flex; gap: 10px; margin-right: 20px;">
                <a href="financial.php" class="btn-reset" style="background: var(--primary-light); color: var(--primary); border-color: var(--gray-border);"><i class="fa-solid fa-arrow-left"></i> Back to Dashboard</a>
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
                    </div>
                    <a href="logout.php" class="dropdown-item text-danger"><i class="fa-solid fa-arrow-right-from-bracket" style="width:16px;"></i> Secure Logout</a>
                </div>
            </div>
        </div>

        <div class="content-area">

            <div class="toolbar">
                <form method="GET" style="display: flex; gap: 15px; flex-wrap: wrap; width: 100%; align-items: center;">
                    <div class="filter-group">
                        <select name="type" class="form-control">
                            <option value="ALL" <?= $filter_type == 'ALL' ? 'selected' : '' ?>>All Transactions</option>
                            <option value="INCOME" <?= $filter_type == 'INCOME' ? 'selected' : '' ?>>Income Only</option>
                            <option value="EXPENSE" <?= $filter_type == 'EXPENSE' ? 'selected' : '' ?>>Expenses (Bills)</option>
                            <option value="CHECK" <?= $filter_type == 'CHECK' ? 'selected' : '' ?>>Check Vouchers</option>
                        </select>
                    </div>

                    <div class="filter-group">
                        <input type="date" name="start_date" class="form-control" value="<?= htmlspecialchars($start_date) ?>" placeholder="Start Date">
                        <span style="color: #94a3b8; font-size: 12px; font-weight: 600;">TO</span>
                        <input type="date" name="end_date" class="form-control" value="<?= htmlspecialchars($end_date) ?>" placeholder="End Date">
                    </div>

                    <div class="filter-group" style="flex: 1;">
                        <div style="position: relative; width: 100%;">
                            <i class="fa-solid fa-search" style="position: absolute; left: 12px; top: 11px; color: #94a3b8; font-size: 13px;"></i>
                            <input type="text" name="search" class="form-control" placeholder="Search Payee, Reference, or Description..." value="<?= htmlspecialchars($search) ?>" style="padding-left: 32px; width: 100%;">
                        </div>
                    </div>

                    <div class="filter-group">
                        <button type="submit" class="btn-filter"><i class="fa-solid fa-filter"></i> Apply</button>
                        <a href="transaction_history.php" class="btn-reset">Reset</a>
                    </div>
                </form>
            </div>

            <div class="summary-wrapper">
                <div class="summary-card">
                    <div class="summary-icon si-inc"><i class="fa-solid fa-arrow-trend-up"></i></div>
                    <div>
                        <span style="font-size: 11px; color: #64748b; font-weight: 700; text-transform: uppercase;">Filtered Income</span>
                        <div style="font-size: 20px; font-weight: 800; color: #1e293b;">₱<?= number_format($total_income_view, 2) ?></div>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="summary-icon si-exp"><i class="fa-solid fa-arrow-trend-down"></i></div>
                    <div>
                        <span style="font-size: 11px; color: #64748b; font-weight: 700; text-transform: uppercase;">Filtered Expenses</span>
                        <div style="font-size: 20px; font-weight: 800; color: #1e293b;">₱<?= number_format($total_expense_view, 2) ?></div>
                    </div>
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Reference / OR</th>
                            <th>Type</th>
                            <th>Category / Payee</th>
                            <th style="width: 30%;">Description</th>
                            <th>Amount</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if(!empty($transactions)): ?>
                            <?php foreach($transactions as $t): ?>
                            <tr>
                                <td style="font-weight: 600; color: #64748b;"><?= date('M d, Y', strtotime($t['transaction_date'])) ?></td>
                                
                                <td>
                                    <strong style="color: #1e293b;"><?= htmlspecialchars($t['or_number'] ?? 'N/A') ?></strong>
                                    <?php if($t['is_check'] == 1): ?>
                                        <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">CHK: <?= htmlspecialchars($t['check_number']) ?></div>
                                    <?php endif; ?>
                                </td>
                                
                                <td>
                                    <?php 
                                        if($t['type'] == 'INCOME') {
                                            echo '<span class="badge b-inc">INCOME</span>';
                                        } else {
                                            if($t['is_check'] == 1) {
                                                echo '<span class="badge b-chk">CHECK VOUCHER</span>';
                                            } else {
                                                echo '<span class="badge b-exp">CASH EXPENSE</span>';
                                            }
                                        }
                                    ?>
                                </td>

                                <td>
                                    <?php if(!empty($t['payee'])): ?>
                                        <div style="font-weight: 700; color: #334155;"><?= htmlspecialchars($t['payee']) ?></div>
                                    <?php endif; ?>
                                    <div style="font-size: 11px; color: #64748b; font-weight: 600; margin-top: 2px;">
                                        <i class="fa-solid fa-tag"></i> <?= htmlspecialchars($t['category_name'] ?? 'Uncategorized') ?>
                                    </div>
                                </td>

                                <td style="color: #475569; line-height: 1.4;">
                                    <?= htmlspecialchars($t['description']) ?>
                                </td>

                                <td class="<?= $t['type'] == 'INCOME' ? 'amount-pos' : 'amount-neg' ?>">
                                    <?= $t['type'] == 'INCOME' ? '+' : '-' ?> ₱<?= number_format($t['amount'], 2) ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="6" style="text-align: center; padding: 50px; color: #94a3b8;">
                                    <i class="fa-solid fa-folder-open" style="font-size: 34px; margin-bottom: 15px; display: block; color: #cbd5e1;"></i>
                                    <span style="font-weight: 500;">No transactions found matching your filters.</span>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

        </div>
    </div>
</body>
</html>