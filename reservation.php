<?php
// reservation.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    header("Location: login.php");
    exit();
}

$status_filter = $_GET['status'] ?? 'ALL';
$where_sql = "1";
if($status_filter != 'ALL'){
    $where_sql = "r.status = '$status_filter'";
}

// Alert Handling
$alert_msg = "";
$alert_type = "";
if(isset($_GET['msg'])){
    if($_GET['msg'] == 'approved') { 
        $alert_msg = "Reservation approved! An email has been sent to the buyer notifying them of their 20-day down payment deadline."; 
        $alert_type = "success"; 
    }
    if($_GET['msg'] == 'rejected') { 
        $alert_msg = "Reservation rejected. Lot returned to available inventory."; 
        $alert_type = "error"; 
    }
}

// Fetch Reservations
$query = "SELECT r.*, u.fullname, u.email as user_email, l.block_no, l.lot_no, l.total_price, l.location 
          FROM reservations r 
          JOIN users u ON r.user_id = u.id 
          JOIN lots l ON r.lot_id = l.id 
          WHERE $where_sql 
          ORDER BY r.reservation_date DESC";

$res = $conn->query($query);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Reservations | JEJ Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <style>
        :root {
            /* NATURE GREEN THEME (Restored as Primary) */
            --primary: #2e7d32; /* Leaf Green */
            --primary-light: #e8f5e9; /* Soft moss green */
            --dark: #1b5e20; /* Deep forest green */
            --gray-light: #f1f8e9; /* Faint earthy green/white */
            --gray-border: #c8e6c9; /* Light green border */
            --text-muted: #607d8b; /* Stone slate gray for text */
            
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

        /* Table Styling */
        .table-container { background: white; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); overflow: hidden; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px 24px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; background: var(--gray-light); border-bottom: 1px solid var(--gray-border); letter-spacing: 0.5px;}
        td { padding: 16px 24px; border-bottom: 1px solid var(--gray-border); color: #37474f; font-size: 14px; vertical-align: top; }
        tr:hover td { background: #fdfdfd; }
        tr:last-child td { border-bottom: none; }

        /* Tabs */
        .tabs { display: flex; gap: 12px; margin-bottom: 25px; flex-wrap: wrap;}
        .tab-link { padding: 10px 20px; border-radius: 8px; font-size: 13px; font-weight: 600; text-decoration: none; color: #455a64; background: white; border: 1px solid var(--gray-border); transition: 0.2s; box-shadow: var(--shadow-sm);}
        .tab-link.active { background: var(--primary); color: white; border-color: var(--primary); box-shadow: 0 4px 10px rgba(46, 125, 50, 0.2); }
        .tab-link:hover:not(.active) { background: var(--gray-light); color: var(--primary); }

        /* Badges (Nature tones) */
        .status-badge { padding: 6px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; letter-spacing: 0.3px; display: inline-block;}
        .status-PENDING { background: #fff3e0; color: #e65100; } /* Orange/Wood */
        .status-APPROVED { background: #e8f5e9; color: #2e7d32; } /* Green */
        .status-REJECTED { background: #ffebee; color: #c62828; } /* Red/Autumn */

        /* Document Buttons - Added Sky Blue Color to stand out from the green */
        .btn-doc { 
            display: inline-flex; align-items: center; gap: 5px; padding: 8px 12px; 
            background: #e0f2fe; color: #0284c7; border: 1px solid #bae6fd; 
            border-radius: 6px; font-size: 12px; font-weight: 600; 
            text-decoration: none; margin-right: 5px; margin-bottom: 5px; cursor: pointer; transition: 0.2s;
        }
        .btn-doc:hover { background: #bae6fd; color: #0369a1; }
        
        /* Action Buttons - Distinct Semantic Colors */
        .action-forms { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
        .btn-action { padding: 8px 12px; border:none; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; color: white; display: inline-flex; align-items: center; gap: 5px; transition: 0.2s; box-shadow: var(--shadow-sm);}
        
        .btn-approve { background: #10b981; } .btn-approve:hover { background: #059669; transform: translateY(-1px); } /* Vibrant Emerald */
        .btn-reject { background: #ef4444; } .btn-reject:hover { background: #dc2626; transform: translateY(-1px); } /* Vibrant Red */
        .btn-receipt { background: #64748b; color: white; text-decoration:none; } .btn-receipt:hover { background: #475569; transform: translateY(-1px); } /* Slate */
        .btn-terms { background: #3b82f6; color: white; text-decoration:none; } .btn-terms:hover { background: #2563eb; transform: translateY(-1px); } /* Vibrant Blue */

        /* Modal Styles */
        .doc-modal {
            display: none; position: fixed; z-index: 2000; inset: 0; 
            background-color: rgba(0,0,0,0.85); backdrop-filter: blur(3px); align-items: center; justify-content: center;
        }
        .doc-modal img { max-width: 90%; max-height: 90vh; border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); object-fit: contain; }
        .doc-close { position: absolute; top: 20px; right: 30px; color: white; font-size: 40px; cursor: pointer; transition: 0.2s; }
        .doc-close:hover { color: #d84315; transform: scale(1.1); }
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
            <a href="reservation.php" class="menu-link active"><i class="fa-solid fa-file-signature"></i> Reservations</a>
            <a href="master_list.php" class="menu-link"><i class="fa-solid fa-map-location-dot"></i> Master List / Map</a>
            <a href="admin.php?view=inventory" class="menu-link"><i class="fa-solid fa-plus-circle"></i> Add Property</a>
            <a href="financial.php" class="menu-link"><i class="fa-solid fa-coins"></i> Financials</a>
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
                <h1>Reservation Management</h1>
                <p>Review, approve, or reject property reservations.</p>
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

            <div class="tabs">
                <a href="reservation.php?status=ALL" class="tab-link <?= $status_filter=='ALL'?'active':'' ?>">All Requests</a>
                <a href="reservation.php?status=PENDING" class="tab-link <?= $status_filter=='PENDING'?'active':'' ?>">Pending</a>
                <a href="reservation.php?status=APPROVED" class="tab-link <?= $status_filter=='APPROVED'?'active':'' ?>">Approved</a>
                <a href="reservation.php?status=REJECTED" class="tab-link <?= $status_filter=='REJECTED'?'active':'' ?>">Rejected</a>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 25%;">Buyer Information</th>
                            <th style="width: 20%;">Property Details</th>
                            <th style="width: 20%;">Documents (Click to View)</th>
                            <th style="width: 10%;">Status</th>
                            <th style="width: 25%;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if($res && $res->num_rows > 0): ?>
                            <?php while($row = $res->fetch_assoc()): ?>
                            <tr>
                                <td>
                                    <div style="font-weight: 700; color: #263238; margin-bottom: 5px; font-size: 14px;">
                                        <?= htmlspecialchars($row['fullname']) ?>
                                    </div>
                                    <div style="font-size:12px; color:#546e7a; margin-bottom: 2px;"><i class="fa-solid fa-phone" style="font-size:11px; color:#90a4ae; width: 15px;"></i> <?= $row['contact_number'] ?></div>
                                    <div style="font-size:12px; color:#546e7a;"><i class="fa-solid fa-envelope" style="font-size:11px; color:#90a4ae; width: 15px;"></i> <?= $row['email'] ?? $row['user_email'] ?></div>
                                </td>

                                <td>
                                    <div style="font-weight: 700; color: var(--primary);">Block <?= $row['block_no'] ?>, Lot <?= $row['lot_no'] ?></div>
                                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;"><?= $row['location'] ?></div>
                                    <div style="font-weight: 700; font-size: 13px; margin-top: 6px; color: #263238;">₱<?= number_format($row['total_price']) ?></div>
                                </td>

                                <td>
                                    <button class="btn-doc" onclick="showDoc('uploads/<?= $row['payment_proof'] ?>')" title="View Proof of Payment">
                                        <i class="fa-solid fa-receipt"></i> Proof
                                    </button>
                                    <button class="btn-doc" onclick="showDoc('uploads/<?= $row['valid_id_file'] ?>')" title="View Valid ID">
                                        <i class="fa-solid fa-id-card"></i> ID
                                    </button>
                                    <button class="btn-doc" onclick="showDoc('uploads/<?= $row['selfie_with_id'] ?>')" title="View Selfie">
                                        <i class="fa-solid fa-camera"></i> Selfie
                                    </button>
                                </td>

                                <td>
                                    <span class="status-badge status-<?= $row['status'] ?>"><?= $row['status'] ?></span>
                                </td>

                                <td>
                                    <div class="action-forms">
                                        
                                        <a href="receipt.php?id=<?= $row['id'] ?>" target="_blank" class="btn-action btn-receipt">
                                            <i class="fa-solid fa-print"></i> Receipt
                                        </a>

                                        <?php if($row['status'] == 'APPROVED'): ?>
                                            <a href="payment_terms.php?res_id=<?= $row['id'] ?>" class="btn-action btn-terms">
                                                <i class="fa-solid fa-calculator"></i> Terms
                                            </a>
                                        <?php endif; ?>

                                        <?php if($row['status'] == 'PENDING'): ?>
                                            <form action="actions.php" method="POST" style="margin: 0;" onsubmit="return confirm('Approve this reservation? This will record the income AND automatically email the buyer about their 20-day down payment deadline.')">
                                                <input type="hidden" name="action" value="approve_res">
                                                <input type="hidden" name="res_id" value="<?= $row['id'] ?>">
                                                <input type="hidden" name="lot_id" value="<?= $row['lot_id'] ?>">
                                                <button class="btn-action btn-approve" title="Approve"><i class="fa-solid fa-check"></i> Approve</button>
                                            </form>
                                            <form action="actions.php" method="POST" style="margin: 0;" onsubmit="return confirm('Reject this reservation?')">
                                                <input type="hidden" name="action" value="reject_res">
                                                <input type="hidden" name="res_id" value="<?= $row['id'] ?>">
                                                <button class="btn-action btn-reject" title="Reject"><i class="fa-solid fa-xmark"></i> Reject</button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr><td colspan="5" style="text-align: center; padding: 50px; color: var(--text-muted);">
                                <i class="fa-solid fa-folder-open" style="font-size: 34px; margin-bottom: 15px; display: block; color: #cfd8dc;"></i>
                                <span style="font-weight: 500;">No reservations found matching this filter.</span>
                            </td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
        </div>
    </div>

    <div id="docModal" class="doc-modal" onclick="closeDoc()">
        <span class="doc-close">&times;</span>
        <img id="docImage" src="">
    </div>

    <script>
        function showDoc(src) {
            document.getElementById('docImage').src = src;
            document.getElementById('docModal').style.display = 'flex';
        }
        function closeDoc() {
            document.getElementById('docModal').style.display = 'none';
        }
        document.addEventListener('keydown', function(e){
            if(e.key === "Escape") closeDoc();
        });
    </script>

</body>
</html>