<?php
// accounts.php - JEJ/EcoEstates Admin Accounts Management
include 'config.php';

// 1. Basic Access Control
if (!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])) {
    header("Location: admin.php?view=dashboard");
    exit();
}

$active_page = "accounts";
$current_role = $_SESSION['role'];

// 2. Fetch Manager Permissions globally for the Sidebar
$sidebar_perms = [];
if ($_SESSION['role'] == 'MANAGER') {
    $p_stmt = $conn->prepare("SELECT * FROM manager_permissions WHERE user_id = ?");
    $p_stmt->bind_param("i", $_SESSION['user_id']);
    $p_stmt->execute();
    $sidebar_perms = $p_stmt->get_result()->fetch_assoc() ?: [];
}

// 3. Permission Helper Function
function canView($module) {
    global $sidebar_perms;
    if ($_SESSION['role'] == 'SUPER ADMIN' || $_SESSION['role'] == 'ADMIN') return true;
    
    if ($_SESSION['role'] == 'MANAGER') {
        if (empty($sidebar_perms)) return false; // No permissions set yet
        
        $prefix = explode('_', $module)[0];
        if (!empty($sidebar_perms[$prefix . '_full'])) return true; // Has full access to category
        
        return !empty($sidebar_perms[$module]); // Has specific access
    }
    return false;
}

// 4. Strict Page-Level Protection
// If a Manager has no User management permissions, kick them to dashboard
if ($_SESSION['role'] == 'MANAGER') {
    if (!canView('usr_buyers') && !canView('usr_admins') && !canView('usr_promote')) {
        header("Location: admin.php?view=dashboard");
        exit();
    }
}

// --- HANDLING AJAX POST REQUESTS ---
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    header('Content-Type: application/json');

    // Create New Account
    if ($action == 'create_account') {
        $fullname = $_POST['fullname'];
        $email = $_POST['email'];
        $phone = $_POST['phone'];
        $password = $_POST['password'];
        $role = $_POST['role'];

        if (in_array($role, ['ADMIN', 'SUPER ADMIN']) && $current_role != 'SUPER ADMIN') {
            echo json_encode(['status' => 'error', 'message' => 'Unauthorized to create high-level roles.']);
            exit();
        }

        $chk = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $chk->bind_param("s", $email);
        $chk->execute();
        if ($chk->get_result()->num_rows > 0) {
            echo json_encode(['status' => 'error', 'message' => 'Email address already registered.']);
            exit();
        }

        $hashed_pass = md5($password); 
        $stmt = $conn->prepare("INSERT INTO users (fullname, email, phone, password, role) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $fullname, $email, $phone, $hashed_pass, $role);

        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'message' => 'Account created successfully!']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Database error during creation.']);
        }
        exit();
    }

    // Update Account Basic Info
    if ($action == 'update_account') {
        $user_id = $_POST['user_id'];
        $fullname = $_POST['fullname'];
        $email = $_POST['email'];
        $phone = $_POST['phone'];
        $role = $_POST['role'];

        if($user_id == $_SESSION['user_id']){
            $role = $_SESSION['role']; 
        }

        $stmt = $conn->prepare("UPDATE users SET fullname=?, email=?, phone=?, role=? WHERE id=?");
        $stmt->bind_param("ssssi", $fullname, $email, $phone, $role, $user_id);

        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'message' => 'Account updated successfully!']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Database error during update.']);
        }
        exit();
    }
    
    // Quick Promote / Demote
    if ($action == 'change_role') {
        $user_id = $_POST['user_id'];
        $new_role = $_POST['new_role'];

        if($user_id == $_SESSION['user_id']){
            echo json_encode(['status' => 'error', 'message' => 'Cannot change your own role.']);
            exit();
        }

        $stmt = $conn->prepare("UPDATE users SET role=? WHERE id=?");
        $stmt->bind_param("si", $new_role, $user_id);
        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'message' => "User successfully changed to $new_role!"]);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Database error during role update.']);
        }
        exit();
    }

    // Save Manager Permissions
    if ($action == 'save_manager_permissions') {
        $user_id = $_POST['user_id'];
        $perms = [
            'inv_full', 'inv_property', 'inv_status', 'inv_price',
            'res_full', 'res_process', 'res_status', 'res_terms',
            'fin_full', 'fin_process', 'fin_review', 'fin_checks', 'fin_accounts',
            'usr_full', 'usr_buyers', 'usr_promote', 'usr_admins'
        ];

        $vals = []; $types = "i"; $vals[] = &$user_id;

        foreach($perms as $p){
            $v = isset($_POST[$p]) ? 1 : 0;
            $vals[] = $v;
            $types .= "i";
        }

        $sql = "INSERT INTO manager_permissions (user_id, " . implode(", ", $perms) . ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE ";
        $update_parts = [];
        foreach($perms as $p){ $update_parts[] = "$p = VALUES($p)"; }
        $sql .= implode(", ", $update_parts);

        $stmt = $conn->prepare($sql);
        call_user_func_array(array($stmt, 'bind_param'), array_merge(array($types), $vals));

        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'message' => 'Permissions saved successfully!']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Database error saving permissions.']);
        }
        exit();
    }

    // Get Account Details & Permissions
    if($action == 'get_account_details'){
        $id = $_POST['id'];
        
        $u_stmt = $conn->prepare("SELECT id, fullname, email, phone, role FROM users WHERE id = ?");
        $u_stmt->bind_param("i", $id);
        $u_stmt->execute();
        $user = $u_stmt->get_result()->fetch_assoc();

        if(!$user) { echo json_encode(['status' => 'error']); exit(); }

        $permissions = null;
        if($user['role'] == 'MANAGER'){
            $p_stmt = $conn->prepare("SELECT * FROM manager_permissions WHERE user_id = ?");
            $p_stmt->bind_param("i", $id);
            $p_stmt->execute();
            $permissions = $p_stmt->get_result()->fetch_assoc();
        }

        echo json_encode(['status' => 'success', 'user' => $user, 'permissions' => $permissions]);
        exit();
    }
}

// Fetch Accounts List
$where_clauses = [];
if (isset($_GET['search']) && !empty($_GET['search'])) {
    $s = $conn->real_escape_string($_GET['search']);
    $where_clauses[] = "(fullname LIKE '%$s%' OR email LIKE '%$s%' OR phone LIKE '%$s%')";
}
if (isset($_GET['role']) && !empty($_GET['role'])) {
    $r = $conn->real_escape_string($_GET['role']);
    $where_clauses[] = "role = '$r'";
}
$where_sql = !empty($where_clauses) ? "WHERE " . implode(" AND ", $where_clauses) : "";

$accounts_query = "SELECT id, fullname, email, phone, role, created_at FROM users $where_sql ORDER BY created_at DESC";
$accounts_result = $conn->query($accounts_query);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Accounts | EcoEstates Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js"></script>
    <style>
        :root {
            --primary: #2e7d32; 
            --primary-dark: #1b5e20;
            --primary-light: #e8f5e9;
            --bg-gray: #f4f7f6;
            --border: #e2e8f0;
            --text-dark: #1a202c;
            --text-muted: #718096;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }

        body { font-family: 'Inter', sans-serif; background: var(--bg-gray); color: var(--text-dark); margin: 0; padding: 0; display: flex;}
        
        /* Sidebar Styling */
        .sidebar { width: 260px; background: #ffffff; border-right: 1px solid var(--border); display: flex; flex-direction: column; position: fixed; height: 100vh; top: 0; left: 0; z-index: 100; box-shadow: var(--shadow); }
        .brand-box { padding: 25px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; }
        .sidebar-menu { padding: 20px 15px; flex: 1; overflow-y: auto; }
        .menu-link { display: flex; align-items: center; gap: 12px; padding: 12px 18px; color: #455a64; text-decoration: none; font-weight: 500; font-size: 14px; border-radius: 10px; margin-bottom: 6px; transition: all 0.2s ease; }
        .menu-link:hover { background: var(--primary-light); color: var(--primary); }
        .menu-link.active { background: var(--primary-light); color: var(--primary); font-weight: 600; border-left: 4px solid var(--primary); }
        .menu-link i { width: 20px; text-align: center; font-size: 16px; opacity: 0.8; }

        .main-content { padding: 40px; margin-left: 260px; width: 100%; box-sizing: border-box; } 
        @media (max-width: 992px) { .main-content { margin-left: 0; padding: 20px; } .sidebar { display: none; } }

        .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .page-header h1 { font-weight: 800; font-size: 28px; color: var(--text-dark); margin: 0; letter-spacing: -0.5px; }
        
        .card { background: #fff; border-radius: 16px; box-shadow: var(--shadow); border: 1px solid var(--border); overflow: hidden; }
        .card-header { padding: 20px 25px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #fafbfc; }
        .card-header h2 { font-size: 16px; font-weight: 700; color: var(--primary-dark); margin: 0; text-transform: uppercase; letter-spacing: 0.5px; }

        .filters-group { display: flex; gap: 15px; }
        .filter-control { padding: 10px 15px; border-radius: 8px; border: 1px solid var(--border); font-family: inherit; font-size: 14px; }
        .filter-control:focus { outline: none; border-color: var(--primary); }

        .modern-table { width: 100%; border-collapse: collapse; font-size: 14px; }
        .modern-table th { text-align: left; padding: 18px 25px; background: #fafbfc; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; font-size: 12px; border-bottom: 1px solid var(--border); }
        .modern-table td { padding: 18px 25px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        .modern-table tr:hover td { background-color: #fcfdfe; }

        .badge { padding: 6px 12px; border-radius: 20px; font-weight: 600; font-size: 12px; display: inline-flex; align-items: center; gap: 6px; }
        .role-super-admin { background: #fee2e2; color: #dc2626; }
        .role-admin { background: #e0f2fe; color: #0284c7; }
        .role-manager { background: var(--primary-light); color: var(--primary); }
        .role-buyer { background: #f1f5f9; color: #64748b; }

        .btn { padding: 12px 20px; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; border: none; display: inline-flex; align-items: center; gap: 8px; font-family: inherit; }
        .btn-primary { background: var(--primary); color: white; }
        
        .action-btns { display: flex; gap: 6px; }
        .btn-action { padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; border: none; display: inline-flex; align-items: center; gap: 5px; color: white; transition: 0.2s; font-family: 'Inter', sans-serif;}
        .btn-edit { background: #0284c7; } .btn-edit:hover { background: #0369a1; }
        .btn-delete { background: #dc2626; } .btn-delete:hover { background: #b91c1c; }
        .btn-promote { background: #10b981; } .btn-promote:hover { background: #059669; }
        .btn-demote { background: #64748b; } .btn-demote:hover { background: #475569; }
        .btn-perms { background: #d97706; } .btn-perms:hover { background: #b45309; }

        .modal { display: none; position: fixed; z-index: 2000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); backdrop-filter: blur(4px); }
        .modal-content { background-color: #fff; margin: 5vh auto; padding: 0; border-radius: 16px; width: 90%; max-width: 650px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1); }
        .modal-header { padding: 20px 30px; background: #fafbfc; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
        .modal-header h2 { margin: 0; font-size: 18px; font-weight: 800; }
        .close-modal { color: var(--text-muted); font-size: 24px; font-weight: bold; cursor: pointer; }
        .modal-body { padding: 30px; }
        .modal-footer { padding: 20px 30px; background: #fafbfc; border-top: 1px solid var(--border); text-align: right; }

        .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .form-group.full-width { grid-column: span 2; }
        .form-label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px; }
        .form-control { width: 100%; padding: 12px 15px; border: 1px solid var(--border); border-radius: 8px; font-size: 14px; box-sizing: border-box; }

        .modal-permissions { max-width: 850px; }
        .perm-header-summary { display: flex; gap: 15px; align-items: center; background: var(--primary-light); padding: 15px 25px; border-radius: 12px; margin-bottom: 25px; border: 1px solid #c8e6c9; }
        .perm-header-summary h3 { margin: 0; font-size: 16px; color: var(--primary-dark); }
        .permissions-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
        .perm-section { border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
        .perm-section-header { padding: 15px 20px; background: #f8fafc; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; font-weight: 700; }
        .perm-list { padding: 15px 20px; }
        .perm-item { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
        
        .checkbox-container { display: block; position: relative; padding-left: 30px; cursor: pointer; font-size: 14px; font-weight: 500; }
        .checkbox-container input { position: absolute; opacity: 0; cursor: pointer; }
        .checkmark { position: absolute; top: 0; left: 0; height: 20px; width: 20px; border: 2px solid #cbd5e1; border-radius: 6px; }
        .checkbox-container input:checked ~ .checkmark { background-color: var(--primary); border-color: var(--primary); }
        .checkmark:after { content: ""; position: absolute; display: none; left: 6px; top: 2px; width: 5px; height: 10px; border: solid white; border-width: 0 2px 2px 0; transform: rotate(45deg); }
        .checkbox-container input:checked ~ .checkmark:after { display: block; }
        .perm-item.full-access { border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 15px; color: var(--primary-dark); }

        #alert-area { position: fixed; top: 20px; right: 20px; z-index: 3000; width: 350px; }
        .alert { padding: 15px 20px; border-radius: 10px; color: white; margin-bottom: 10px; display: flex; align-items: center; gap: 12px; font-weight: 500; font-size: 14px; }
        .alert-success { background-color: #10b981; }
        .alert-error { background-color: #ef4444; }

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
            <small style="padding: 0 15px; color: #90a4ae; font-weight: 700; font-size: 11px; display: block; margin-bottom: 12px;">MAIN MENU</small>
            
            <a href="admin.php?view=dashboard" class="menu-link"><i class="fa-solid fa-chart-pie"></i> Dashboard</a>
            
            <?php if(canView('res_process') || canView('res_status') || canView('res_terms')): ?>
                <a href="reservation.php" class="menu-link"><i class="fa-solid fa-file-signature"></i> Reservations</a>
            <?php endif; ?>

            <?php if(canView('inv_property') || canView('inv_status') || canView('inv_price')): ?>
                <a href="master_list.php" class="menu-link"><i class="fa-solid fa-map-location-dot"></i> Master List / Map</a>
                <a href="admin.php?view=inventory" class="menu-link"><i class="fa-solid fa-plus-circle"></i> Add Property</a>
            <?php endif; ?>

            <?php if(canView('fin_process') || canView('fin_review') || canView('fin_checks')): ?>
                <a href="financial.php" class="menu-link"><i class="fa-solid fa-coins"></i> Financials</a>
                <a href="payment_tracking.php" class="menu-link"><i class="fa-solid fa-file-invoice-dollar"></i> Payment Tracking</a>
            <?php endif; ?>
            
            <?php if(canView('usr_buyers') || canView('usr_admins') || canView('usr_promote')): ?>
                <small style="padding: 0 15px; color: #90a4ae; font-weight: 700; font-size: 11px; display: block; margin-top: 25px; margin-bottom: 12px;">MANAGEMENT</small>
                <a href="accounts.php" class="menu-link active"><i class="fa-solid fa-users-gear"></i> Accounts</a>
            <?php endif; ?>

            <?php if($_SESSION['role'] == 'SUPER ADMIN' || $_SESSION['role'] == 'ADMIN'): ?>
                <a href="delete_history.php" class="menu-link"><i class="fa-solid fa-trash-can"></i> Delete History</a>
            <?php endif; ?>
        </div>
    </div>
    
    <div class="main-content">
        
        <div id="alert-area"></div>

        <div class="page-header">
            <h1>User Accounts</h1>
            <?php if(canView('usr_promote') || canView('usr_admins')): ?>
            <button class="btn btn-primary" onclick="openCreateModal()">
                <i class="fa-solid fa-user-plus"></i> Create New Account
            </button>
            <?php endif; ?>
        </div>

        <div class="card">
            <div class="card-header">
                <h2>System Users List</h2>
                
                <form method="GET" class="filters-group">
                    <input type="text" name="search" class="filter-control" placeholder="Search name, email..." value="<?= htmlspecialchars($_GET['search'] ?? '') ?>">
                    <select name="role" class="filter-control" onchange="this.form.submit()">
                        <option value="">All Roles</option>
                        <option value="SUPER ADMIN" <?= ($_GET['role'] ?? '') == 'SUPER ADMIN' ? 'selected' : '' ?>>Super Admin</option>
                        <option value="ADMIN" <?= ($_GET['role'] ?? '') == 'ADMIN' ? 'selected' : '' ?>>Admin</option>
                        <option value="MANAGER" <?= ($_GET['role'] ?? '') == 'MANAGER' ? 'selected' : '' ?>>Manager</option>
                        <option value="BUYER" <?= ($_GET['role'] ?? '') == 'BUYER' ? 'selected' : '' ?>>Buyer</option>
                    </select>
                </form>
            </div>
            
            <div style="overflow-x: auto;">
                <table class="modern-table">
                    <thead>
                        <tr>
                            <th>Name / Contact</th>
                            <th>Role</th>
                            <th>Created At</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if($accounts_result && $accounts_result->num_rows > 0): ?>
                            <?php while($row = $accounts_result->fetch_assoc()): ?>
                                <tr>
                                    <td>
                                        <div style="font-weight: 700; color: var(--text-dark);"><?= htmlspecialchars($row['fullname']) ?></div>
                                        <div style="color: var(--text-muted); font-size: 13px; margin-top: 2px;">
                                            <i class="fa-regular fa-envelope" style="width: 16px;"></i> <?= htmlspecialchars($row['email']) ?><br>
                                            <i class="fa-solid fa-phone" style="width: 16px;"></i> <?= htmlspecialchars($row['phone'] ?? 'N/A') ?>
                                        </div>
                                    </td>
                                    <td>
                                        <?php
                                        $rc = strtolower(str_replace(' ', '-', $row['role']));
                                        echo "<span class='badge role-$rc'>" . htmlspecialchars($row['role']) . "</span>";
                                        ?>
                                    </td>
                                    <td style="color: var(--text-muted);">
                                        <?= date('M d, Y', strtotime($row['created_at'])) ?>
                                    </td>
                                    <td>
                                        <div class="action-btns">
                                            
                                            <?php if(canView('usr_admins') || canView('usr_buyers')): ?>
                                                <button class="btn-action btn-edit" onclick="openEditModal(<?= $row['id'] ?>)">
                                                    <i class="fa-solid fa-pen"></i> Edit
                                                </button>
                                            <?php endif; ?>

                                            <?php if($row['role'] == 'BUYER' && canView('usr_promote')): ?>
                                                <button class="btn-action btn-promote" onclick="changeRole(<?= $row['id'] ?>, 'MANAGER')">
                                                    <i class="fa-solid fa-arrow-up"></i> Promote
                                                </button>
                                            <?php endif; ?>

                                            <?php if($row['role'] == 'MANAGER' && canView('usr_promote')): ?>
                                                <button class="btn-action btn-perms" onclick="openPermissionsModal(<?= $row['id'] ?>)">
                                                    <i class="fa-solid fa-shield"></i> Perms
                                                </button>
                                                <button class="btn-action btn-demote" onclick="changeRole(<?= $row['id'] ?>, 'BUYER')">
                                                    <i class="fa-solid fa-arrow-down"></i> Demote
                                                </button>
                                            <?php endif; ?>

                                            <?php if($row['id'] != $_SESSION['user_id'] && canView('usr_admins')): ?>
                                                <button class="btn-action btn-delete" onclick="alert('System restriction: Contact super admin to delete accounts permanently.')">
                                                    <i class="fa-solid fa-trash"></i> Delete
                                                </button>
                                            <?php endif; ?>
                                            
                                        </div>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="4" style="text-align: center; padding: 40px; color: var(--text-muted);">
                                    No accounts found matching your criteria.
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div id="accountModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">Create New Account</h2>
                <span class="close-modal" onclick="closeModal('accountModal')">&times;</span>
            </div>
            <form id="accountForm">
                <input type="hidden" name="action" id="formAction" value="create_account">
                <input type="hidden" name="user_id" id="formUserId" value="">
                
                <div class="modal-body">
                    <div class="form-grid">
                        <div class="form-group full-width">
                            <label class="form-label">Full Name</label>
                            <input type="text" name="fullname" id="f_fullname" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Email Address</label>
                            <input type="email" name="email" id="f_email" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Phone Number</label>
                            <input type="text" name="phone" id="f_phone" class="form-control">
                        </div>
                        <div class="form-group full-width" id="passwordGroup">
                            <label class="form-label">Account Password</label>
                            <input type="password" name="password" id="f_password" class="form-control" required minlength="4">
                        </div>
                        <div class="form-group full-width">
                            <label class="form-label">Account Role</label>
                            <select name="role" id="f_role" class="form-control" required>
                                <option value="BUYER">Buyer (Client)</option>
                                <option value="MANAGER">Manager (Staff)</option>
                                <?php if($current_role == 'SUPER ADMIN'): ?>
                                    <option value="ADMIN">Administrator</option>
                                    <option value="SUPER ADMIN">Super Admin</option>
                                <?php endif; ?>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="submit" class="btn btn-primary" style="background:#0284c7;">
                        Save Account
                    </button>
                </div>
            </form>
        </div>
    </div>

    <div id="permissionsModal" class="modal">
        <div class="modal-content modal-permissions">
            <div class="modal-header">
                <h2>Manager Permissions Setup</h2>
                <span class="close-modal" onclick="closeModal('permissionsModal')">&times;</span>
            </div>
            <form id="permissionsForm">
                <input type="hidden" name="action" value="save_manager_permissions">
                <input type="hidden" name="user_id" id="p_user_id" value="">
                
                <div class="modal-body">
                    <div class="perm-header-summary">
                        <i class="fa-solid fa-user-gear" style="font-size: 30px; color: var(--primary);"></i>
                        <div>
                            <h3>Permission Settings</h3>
                            <p id="p_manager_name" style="margin:0; font-size:13px;">Loading...</p>
                        </div>
                    </div>

                    <div class="permissions-grid">
                        <div class="perm-section">
                            <div class="perm-section-header">Inventory Management</div>
                            <div class="perm-list">
                                <div class="perm-item full-access"><label class="checkbox-container">Full Access<input type="checkbox" name="inv_full" id="p_inv_full" onchange="toggleFullAccess(this, 'inv')"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Manage Property<input type="checkbox" name="inv_property" class="perm-inv"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Lot Status<input type="checkbox" name="inv_status" class="perm-inv"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Adjust Pricing<input type="checkbox" name="inv_price" class="perm-inv"><span class="checkmark"></span></label></div>
                            </div>
                        </div>

                        <div class="perm-section">
                            <div class="perm-section-header">Reservation Management</div>
                            <div class="perm-list">
                                <div class="perm-item full-access"><label class="checkbox-container">Full Access<input type="checkbox" name="res_full" id="p_res_full" onchange="toggleFullAccess(this, 'res')"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Process Reservations<input type="checkbox" name="res_process" class="perm-res"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Approve Requests<input type="checkbox" name="res_status" class="perm-res"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Payment Terms<input type="checkbox" name="res_terms" class="perm-res"><span class="checkmark"></span></label></div>
                            </div>
                        </div>

                        <div class="perm-section">
                            <div class="perm-section-header">Financials & Payments</div>
                            <div class="perm-list">
                                <div class="perm-item full-access"><label class="checkbox-container">Full Access<input type="checkbox" name="fin_full" id="p_fin_full" onchange="toggleFullAccess(this, 'fin')"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Process Payments<input type="checkbox" name="fin_process" class="perm-fin"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Check Vouchers<input type="checkbox" name="fin_checks" class="perm-fin"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Bank Accounts<input type="checkbox" name="fin_accounts" class="perm-fin"><span class="checkmark"></span></label></div>
                            </div>
                        </div>

                        <div class="perm-section">
                            <div class="perm-section-header">Users & Accounts</div>
                            <div class="perm-list">
                                <div class="perm-item full-access"><label class="checkbox-container">Full Access<input type="checkbox" name="usr_full" id="p_usr_full" onchange="toggleFullAccess(this, 'usr')"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Manage Buyers<input type="checkbox" name="usr_buyers" class="perm-usr"><span class="checkmark"></span></label></div>
                                <div class="perm-item"><label class="checkbox-container">Promote Managers<input type="checkbox" name="usr_promote" class="perm-usr"><span class="checkmark"></span></label></div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="submit" class="btn btn-primary">Save Permissions</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function closeModal(id) {
            $(`#${id}`).fadeOut(200);
            if(id === 'accountModal') $('#accountForm')[0].reset();
            if(id === 'permissionsModal') $('#permissionsForm')[0].reset();
        }

        function openCreateModal() {
            $('#modalTitle').text('Create New Account');
            $('#formAction').val('create_account');
            $('#formUserId').val('');
            $('#passwordGroup').show();
            
            // Re-enable and require password for creation
            $('#f_password').prop('disabled', false).prop('required', true); 
            
            $('#accountModal').fadeIn(300);
        }

        function openEditModal(id) {
            $('#modalTitle').text('Edit Account');
            $('#formAction').val('update_account');
            $('#formUserId').val(id);
            $('#passwordGroup').hide(); 
            
            // THE FIX: Completely disable the password field so HTML5 validation ignores it during Edit
            $('#f_password').prop('disabled', true).prop('required', false);

            $.ajax({
                url: 'accounts.php',
                method: 'POST',
                data: { action: 'get_account_details', id: id },
                success: function(response){
                    if(response.status === 'success'){
                        const u = response.user;
                        $('#f_fullname').val(u.fullname);
                        $('#f_email').val(u.email);
                        $('#f_phone').val(u.phone);
                        $('#f_role').val(u.role);
                        $('#accountModal').fadeIn(300);
                    }
                }
            });
        }

        // QUICK PROMOTE / DEMOTE LOGIC
        function changeRole(id, newRole) {
            if(confirm(`Are you sure you want to change this user's role to ${newRole}?`)) {
                $.ajax({
                    url: 'accounts.php',
                    method: 'POST',
                    data: { action: 'change_role', user_id: id, new_role: newRole },
                    success: function(response){
                        if(response.status === 'success'){
                            showAlert('success', response.message);
                            setTimeout(()=> location.reload(), 1000);
                        } else {
                            showAlert('error', response.message);
                        }
                    }
                });
            }
        }

        $('#accountForm').on('submit', function(e){
            e.preventDefault();
            $.ajax({
                url: 'accounts.php',
                method: 'POST',
                data: $(this).serialize(),
                success: function(response){
                    if(response.status === 'success'){
                        showAlert('success', response.message);
                        setTimeout(()=> location.reload(), 1000);
                    } else {
                        showAlert('error', response.message);
                    }
                }
            });
        });

        function toggleFullAccess(source, sectionPrefix) {
            $(`.perm-${sectionPrefix}`).prop('checked', source.checked);
        }

        function openPermissionsModal(id) {
            $('#p_user_id').val(id);
            $('#permissionsForm')[0].reset();
            
            $.ajax({
                url: 'accounts.php',
                method: 'POST',
                data: { action: 'get_account_details', id: id },
                success: function(response){
                    if(response.status === 'success'){
                        $('#p_manager_name').text(response.user.fullname + " (" + response.user.email + ")");
                        
                        if(response.permissions){
                            for (const key in response.permissions) {
                                if (response.permissions[key] == 1) {
                                    $(`input[name="${key}"]`).prop('checked', true);
                                }
                            }
                        }
                        $('#permissionsModal').fadeIn(300);
                    }
                }
            });
        }

        $('#permissionsForm').on('submit', function(e){
            e.preventDefault();
            $.ajax({
                url: 'accounts.php',
                method: 'POST',
                data: $(this).serialize(),
                success: function(response){
                    if(response.status === 'success'){
                        showAlert('success', response.message);
                        setTimeout(() => closeModal('permissionsModal'), 1000);
                    } else {
                        showAlert('error', response.message);
                    }
                }
            });
        });

        function showAlert(type, message) {
            const bg = type === 'success' ? '#10b981' : '#ef4444';
            const alert = `<div class="alert" style="background:${bg};"><i class="fa-solid fa-circle-info"></i> ${message}</div>`;
            $('#alert-area').html(alert);
            setTimeout(() => $('.alert').fadeOut(500, function() { $(this).remove(); }), 3000);
        }
    </script>
</body>
</html>