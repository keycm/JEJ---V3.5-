<?php
// delete_history.php
include 'config.php';

// Security Check: Only Super Admin and Admin should view delete logs
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN'])){
    header("Location: login.php");
    exit();
}

$alert_msg = "";
$alert_type = "";

// --- RESTORE LOGIC ---
if(isset($_POST['action']) && $_POST['action'] == 'restore'){
    $history_id = (int)$_POST['history_id'];
    
    // Fetch the archived record
    $archived = $conn->query("SELECT * FROM delete_history WHERE id='$history_id'")->fetch_assoc();
    
    if($archived){
        $data = json_decode($archived['record_data'], true);
        $module = $archived['module_name'];
        $success = false;

        if($module == 'Property Inventory'){
            // Restore Lot
            $stmt = $conn->prepare("INSERT INTO lots (id, location, property_type, block_no, lot_no, area, price_per_sqm, total_price, status, property_overview, latitude, longitude, lot_image) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("issssidddssds", 
                $data['id'], $data['location'], $data['property_type'], $data['block_no'], $data['lot_no'], 
                $data['area'], $data['price_per_sqm'], $data['total_price'], $data['status'], 
                $data['property_overview'], $data['latitude'], $data['longitude'], $data['lot_image']
            );
            $success = $stmt->execute();
        } 
        elseif($module == 'User Accounts') {
            // Restore User (Set default password since we didn't save the old hash)
            $default_pass = md5('jej123456');
            $stmt = $conn->prepare("INSERT INTO users (id, fullname, phone, email, password, role) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("isssss", $data['id'], $data['fullname'], $data['phone'], $data['email'], $default_pass, $data['role']);
            $success = $stmt->execute();
        }

        if($success){
            // Remove from archive since it is restored
            $conn->query("DELETE FROM delete_history WHERE id='$history_id'");
            
            // Log Activity
            logActivity($conn, $_SESSION['user_id'], "Restored Data", "Restored $module (ID: {$data['id']}) from Archive.");
            
            $alert_msg = "Record restored successfully!" . ($module == 'User Accounts' ? " Default password is 'jej123456'" : "");
            $alert_type = "success";
        } else {
            $alert_msg = "Failed to restore record. ID might already exist in the live system. Error: " . $conn->error;
            $alert_type = "error";
        }
    }
}

// --- PERMANENT DELETE (SOFT DELETE FROM ADMIN UI) ---
if(isset($_POST['action']) && $_POST['action'] == 'permanent_delete'){
    $history_id = (int)$_POST['history_id'];
    $admin_password_entered = md5($_POST['admin_password']);
    $admin_id = $_SESSION['user_id'];

    // Verify Admin Password
    $verify = $conn->query("SELECT password FROM users WHERE id='$admin_id'")->fetch_assoc();
    
    if($verify && $verify['password'] === $admin_password_entered){
        // Soft Delete: Hide from UI but keep in DB for raw audit logs
        $conn->query("UPDATE delete_history SET is_hidden = 1 WHERE id='$history_id'");
        
        logActivity($conn, $_SESSION['user_id'], "Permanently Deleted Archive", "Hidden archive ID: $history_id from admin panel.");
        
        $alert_msg = "Record permanently removed from Admin Panel.";
        $alert_type = "success";
    } else {
        $alert_msg = "Incorrect Admin Password. Deletion aborted.";
        $alert_type = "error";
    }
}


// Fetch Delete History Records (Ignoring hidden ones)
$query = "SELECT d.*, d.module_name as module, d.record_id, d.record_data, u.fullname as deleted_by_name, u.role as deleted_by_role 
          FROM delete_history d 
          LEFT JOIN users u ON d.deleted_by = u.id 
          WHERE d.is_hidden = 0
          ORDER BY d.deleted_at DESC";

$history_logs = [];
try {
    $res = $conn->query($query);
    if($res && $res->num_rows > 0){
        while($row = $res->fetch_assoc()){
            $history_logs[] = $row;
        }
    }
} catch (Exception $e) {
    // Table might not exist or schema differs, handle silently
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Archive & Delete History | JEJ Admin</title>
    
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

        /* Alerts & Banners */
        .alert-banner { padding: 16px 20px; border-radius: 10px; margin-bottom: 25px; font-weight: 500; font-size: 14px; box-shadow: var(--shadow-sm); display: flex; align-items: center; gap: 12px;}
        .alert-success { background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; }
        .alert-error { background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }

        /* Table Styling */
        .table-container { background: white; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); overflow: hidden; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px 24px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; background: var(--gray-light); border-bottom: 1px solid var(--gray-border); letter-spacing: 0.5px;}
        td { padding: 16px 24px; border-bottom: 1px solid var(--gray-border); color: #37474f; font-size: 14px; vertical-align: middle; }
        tr:hover td { background: #fdfdfd; }
        tr:last-child td { border-bottom: none; }

        /* Badges */
        .badge { padding: 5px 10px; border-radius: 6px; font-size: 10px; font-weight: 800; text-transform: uppercase; display: inline-block; border: 1px solid transparent;}
        .badge-property { background: #d1fae5; color: #059669; border-color: #a7f3d0; } /* Emerald */
        .badge-account { background: #dbeafe; color: #2563eb; border-color: #bfdbfe; } /* Blue */
        .badge-other { background: #f1f5f9; color: #475569; border-color: #e2e8f0; } /* Slate */

        /* Buttons */
        .btn-view { background: #e0f2fe; color: #0284c7; border: 1px solid #bae6fd; padding: 8px 14px; border-radius: 6px; font-size: 12px; font-weight: 700; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 6px;}
        .btn-view:hover { background: #bae6fd; color: #0369a1; transform: translateY(-1px);}

        .btn-restore { background: #10b981; color: white; border: none; padding: 8px 14px; border-radius: 6px; font-size: 12px; font-weight: 700; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 6px; box-shadow: 0 2px 4px rgba(16, 185, 129, 0.2);}
        .btn-restore:hover { background: #059669; transform: translateY(-1px);}

        .btn-perm { background: #ef4444; color: white; border: none; padding: 8px 14px; border-radius: 6px; font-size: 12px; font-weight: 700; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 6px; box-shadow: 0 2px 4px rgba(239, 68, 68, 0.2);}
        .btn-perm:hover { background: #dc2626; transform: translateY(-1px);}

        /* Modal Styles */
        .modal { display: none; position: fixed; z-index: 9999; inset: 0; background: rgba(0, 0, 0, 0.6); backdrop-filter: blur(3px); padding: 30px; overflow-y: auto; align-items: center; justify-content: center;}
        .modal-content { width: 100%; max-width: 600px; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.3); animation: dropAnim 0.2s ease-out forwards;}
        .modal-header { padding: 20px 25px; border-bottom: 1px solid var(--gray-border); display: flex; justify-content: space-between; align-items: center; background: var(--gray-light); }
        .modal-header h2 { margin: 0; font-size: 18px; font-weight: 700; color: var(--dark); }
        .close-btn { background: none; border: none; font-size: 20px; color: #90a4ae; cursor: pointer; transition: 0.2s;}
        .close-btn:hover { color: #ef4444; transform: scale(1.1);}
        
        .data-display { padding: 25px; max-height: 60vh; overflow-y: auto; background: #f8fafc; font-family: monospace; font-size: 13px; color: #334155; line-height: 1.6;}
        .data-row { display: flex; padding: 8px 0; border-bottom: 1px dashed #cbd5e1; }
        .data-row:last-child { border-bottom: none; }
        .data-key { font-weight: 700; color: #0f172a; width: 40%; text-transform: capitalize; }
        .data-val { color: #2563eb; width: 60%; word-break: break-all; }

        .form-control { width: 100%; padding: 10px 14px; border: 1px solid #cbd5e1; border-radius: 8px; font-family: inherit; font-size: 14px; outline: none; transition: 0.2s; box-sizing: border-box; margin-bottom: 15px;}
        .form-control:focus { border-color: #ef4444; box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.15); }
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
            <a href="transaction_history.php" class="menu-link" style="padding-left: 35px; font-size: 13px;"><i class="fa-solid fa-list-ul" style="font-size: 12px;"></i> Ledger List</a>
            <a href="payment_tracking.php" class="menu-link"><i class="fa-solid fa-file-invoice-dollar"></i> Payment Tracking</a>
            
            <small style="padding: 0 15px; color: #90a4ae; font-weight: 700; font-size: 11px; display: block; margin-top: 25px; margin-bottom: 12px; letter-spacing: 0.5px;">MANAGEMENT</small>
            <a href="accounts.php" class="menu-link"><i class="fa-solid fa-users-gear"></i> Accounts</a>
            <a href="delete_history.php" class="menu-link active"><i class="fa-solid fa-trash-can"></i> Delete History</a>
            
            <small style="padding: 0 15px; color: #90a4ae; font-weight: 700; font-size: 11px; display: block; margin-top: 25px; margin-bottom: 12px; letter-spacing: 0.5px;">SYSTEM</small>
            <a href="index.php" class="menu-link" target="_blank"><i class="fa-solid fa-globe"></i> View Website</a>
        </div>
    </div>

    <div class="main-panel">
        
        <div class="top-header">
            <div class="header-title">
                <h1>Archive & Delete History</h1>
                <p>System audit log of safely archived deleted records.</p>
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

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 15%;">Date Deleted</th>
                            <th style="width: 15%;">Module / Type</th>
                            <th style="width: 15%;">Record ID</th>
                            <th style="width: 25%;">Deleted By</th>
                            <th style="width: 30%;">Archived Data Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if(!empty($history_logs)): ?>
                            <?php foreach($history_logs as $log): 
                                $module = $log['module'] ?? $log['record_type'] ?? 'Unknown';
                                $badgeClass = 'badge-other';
                                if (stripos($module, 'account') !== false || stripos($module, 'user') !== false) $badgeClass = 'badge-account';
                                if (stripos($module, 'property') !== false || stripos($module, 'lot') !== false) $badgeClass = 'badge-property';
                            ?>
                            <tr>
                                <td style="font-weight: 600; color: #64748b;">
                                    <?= date('M d, Y', strtotime($log['deleted_at'])) ?><br>
                                    <span style="font-size: 11px; font-weight: 500;"><?= date('h:i A', strtotime($log['deleted_at'])) ?></span>
                                </td>
                                <td>
                                    <span class="badge <?= $badgeClass ?>"><?= htmlspecialchars($module) ?></span>
                                </td>
                                <td style="font-weight: 700; color: var(--primary);">#<?= htmlspecialchars($log['record_id']) ?></td>
                                <td>
                                    <strong style="color: #1e293b; font-size: 13px; display:block;"><?= htmlspecialchars($log['deleted_by_name'] ?? 'System') ?></strong>
                                    <span style="color: #64748b; font-size: 11px;"><?= htmlspecialchars($log['deleted_by_role'] ?? 'ADMIN') ?></span>
                                </td>
                                <td>
                                    <div style="display:flex; gap:8px; flex-wrap: wrap;">
                                        <button class="btn-view" onclick="viewData(this)" data-json='<?= htmlspecialchars($log['data'] ?? $log['record_data'] ?? '{}', ENT_QUOTES, 'UTF-8') ?>'>
                                            <i class="fa-solid fa-eye"></i> View
                                        </button>
                                        
                                        <form method="POST" style="margin:0;" onsubmit="return confirm('Are you sure you want to restore this record back to the live system?');">
                                            <input type="hidden" name="action" value="restore">
                                            <input type="hidden" name="history_id" value="<?= $log['id'] ?>">
                                            <button type="submit" class="btn-restore"><i class="fa-solid fa-rotate-left"></i> Restore</button>
                                        </form>

                                        <button class="btn-perm" onclick="openDeleteModal(<?= $log['id'] ?>)">
                                            <i class="fa-solid fa-trash"></i> Delete
                                        </button>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="5" style="text-align: center; padding: 50px; color: #94a3b8;">
                                    <i class="fa-solid fa-folder-open" style="font-size: 34px; margin-bottom: 15px; display: block; color: #cbd5e1;"></i>
                                    <span style="font-weight: 500;">No deleted records found in the archive.</span>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
        </div>
    </div>

    <div id="dataModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fa-solid fa-database" style="color: #3b82f6; margin-right: 8px;"></i> Archived Record Data</h2>
                <button type="button" class="close-btn" onclick="closeModal('dataModal')"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div class="data-display" id="dataDisplayArea">
                </div>
        </div>
    </div>

    <div id="deleteModal" class="modal">
        <div class="modal-content" style="max-width: 450px;">
            <div class="modal-header" style="background: #fff1f2; border-bottom: 1px solid #ffe4e6;">
                <h2 style="color: #be123c;"><i class="fa-solid fa-triangle-exclamation" style="margin-right: 8px;"></i> Security Verification</h2>
                <button type="button" class="close-btn" onclick="closeModal('deleteModal')"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div style="padding: 25px;">
                <p style="font-size: 13px; color: #475569; margin-top: 0; margin-bottom: 20px; line-height: 1.5;">
                    You are about to permanently hide this record from the Admin Panel. It will remain in the database backend for strict audit compliance, but cannot be restored from this interface.
                </p>
                <form method="POST">
                    <input type="hidden" name="action" value="permanent_delete">
                    <input type="hidden" name="history_id" id="hidden_history_id" value="">
                    
                    <label style="display:block; font-size:12px; font-weight:700; color:#475569; margin-bottom:6px;">Admin Password Required</label>
                    <input type="password" name="admin_password" class="form-control" placeholder="Enter your password to confirm..." required>
                    
                    <button type="submit" style="background: #ef4444; color: white; border: none; padding: 12px; border-radius: 8px; font-weight: 700; font-size: 14px; width: 100%; cursor: pointer; box-shadow: 0 4px 6px rgba(239,68,68,0.2); transition: 0.2s;">
                        <i class="fa-solid fa-trash-can"></i> Confirm Permanent Removal
                    </button>
                </form>
            </div>
        </div>
    </div>

    <script>
        // View Data Modal Logic
        function viewData(btn) {
            const displayArea = document.getElementById('dataDisplayArea');
            displayArea.innerHTML = ''; 

            try {
                // Parse the JSON string hidden in the data-json attribute
                const rawData = btn.getAttribute('data-json');
                const dataObj = JSON.parse(rawData);
                
                // Build a nice HTML representation of the JSON object
                if(Object.keys(dataObj).length > 0) {
                    for (const [key, value] of Object.entries(dataObj)) {
                        // Skip highly sensitive/useless raw hashes if needed
                        if(key === 'password') continue; 

                        let cleanKey = key.replace(/_/g, ' ');
                        let cleanVal = (value === null || value === '') ? '<em style="color:#94a3b8;">null</em>' : value;
                        
                        displayArea.innerHTML += `
                            <div class="data-row">
                                <div class="data-key">${cleanKey}</div>
                                <div class="data-val">${cleanVal}</div>
                            </div>
                        `;
                    }
                } else {
                    displayArea.innerHTML = '<div style="text-align:center; color:#94a3b8; padding:20px;">No detailed data available for this record.</div>';
                }
            } catch (e) {
                displayArea.innerHTML = '<div style="color:#ef4444; padding:20px;">Error parsing archive data.<br><br><small>' + e.message + '</small></div>';
            }

            document.getElementById('dataModal').style.display = 'flex';
        }

        // Delete Password Modal Logic
        function openDeleteModal(historyId) {
            document.getElementById('hidden_history_id').value = historyId;
            document.getElementById('deleteModal').style.display = 'flex';
        }

        // Shared Modal Close Logic
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        window.onclick = function(event) {
            if (event.target == document.getElementById('dataModal')) closeModal('dataModal');
            if (event.target == document.getElementById('deleteModal')) closeModal('deleteModal');
        }
    </script>
</body>
</html>