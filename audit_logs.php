<?php
// audit_logs.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    header("Location: login.php");
    exit();
}

// --- SEARCH & SORT LOGIC ---
$search = isset($_GET['search']) ? $conn->real_escape_string($_GET['search']) : '';
$sort = isset($_GET['sort']) ? $_GET['sort'] : 'desc';

$where_sql = "1=1";
if($search != ''){
    $where_sql .= " AND (a.action LIKE '%$search%' OR a.details LIKE '%$search%' OR u.fullname LIKE '%$search%')";
}

$order_sql = "ORDER BY a.created_at DESC";
if($sort == 'asc'){
    $order_sql = "ORDER BY a.created_at ASC";
}

// Fetch the logs with limit
$query = "SELECT a.*, u.fullname, u.role FROM audit_logs a 
          LEFT JOIN users u ON a.user_id = u.id 
          WHERE $where_sql 
          $order_sql LIMIT 500";
$logs = $conn->query($query);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Logs | JEJ Surveying</title>
    
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

        body { 
            background-color: #fafcf9; 
            min-height: 100vh; 
            font-family: 'Inter', sans-serif; 
            color: #37474f; 
            margin: 0; 
            padding: 0;
        }

        /* Full Width Panel */
        .main-panel { width: 100%; display: flex; flex-direction: column; }
        
        .top-header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            background: #ffffff; 
            padding: 20px 60px; 
            border-bottom: 1px solid var(--gray-border); 
            box-shadow: var(--shadow-sm); 
            z-index: 50; 
        }
        .header-title h1 { font-size: 24px; font-weight: 800; color: var(--dark); margin: 0 0 4px 0; letter-spacing: -0.5px;}
        .header-title p { color: var(--text-muted); font-size: 14px; margin: 0; }

        /* Profile Dropdown */
        .profile-dropdown { position: relative; cursor: pointer; }
        .profile-trigger { display: flex; align-items: center; gap: 12px; padding: 6px 12px; border-radius: 10px; transition: background 0.2s; border: 1px solid transparent; }
        .profile-trigger:hover { background: var(--gray-light); border-color: var(--gray-border); }
        .profile-avatar { width: 40px; height: 40px; background: var(--primary); color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 16px; box-shadow: 0 2px 4px rgba(46, 125, 50, 0.2);}
        
        .dropdown-menu { display: none; position: absolute; right: 0; top: 110%; background: white; border-radius: 12px; box-shadow: var(--shadow-lg); border: 1px solid var(--gray-border); min-width: 200px; z-index: 1000; overflow: hidden; transform-origin: top right; animation: dropAnim 0.2s ease-out forwards; }
        @keyframes dropAnim { 0% { opacity: 0; transform: scale(0.95) translateY(-10px); } 100% { opacity: 1; transform: scale(1) translateY(0); } }
        .profile-dropdown:hover .dropdown-menu { display: block; }
        .dropdown-item { padding: 12px 16px; display: flex; align-items: center; gap: 12px; color: #455a64; text-decoration: none; font-size: 13px; font-weight: 500; transition: background 0.2s; border-left: 3px solid transparent;}
        .dropdown-item:hover { background: var(--primary-light); color: var(--primary); border-left-color: var(--primary); }
        .dropdown-item.text-danger { color: #d84315; }
        .dropdown-item.text-danger:hover { background: #fbe9e7; color: #bf360c; border-left-color: #d84315; }

        .content-area { padding: 40px 60px; flex: 1; }

        /* Toolbar */
        .toolbar { 
            background: white; 
            padding: 20px 25px; 
            border-radius: 16px; 
            border: 1px solid var(--gray-border); 
            box-shadow: var(--shadow-sm); 
            margin-bottom: 25px; 
            display: flex; 
            flex-wrap: wrap; 
            gap: 15px; 
            align-items: center; 
            justify-content: space-between;
        }
        .form-control { padding: 11px 16px; border: 1px solid #cbd5e1; border-radius: 10px; font-family: inherit; font-size: 14px; outline: none; transition: 0.2s; color: #475569;}
        .form-control:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.15); }
        
        .btn-filter { background: var(--primary); color: white; border: none; padding: 11px 22px; border-radius: 10px; font-weight: 600; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 8px;}
        .btn-filter:hover { background: var(--dark); box-shadow: 0 4px 6px rgba(46, 125, 50, 0.2); }
        .btn-reset { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; padding: 11px 22px; border-radius: 10px; font-weight: 600; cursor: pointer; text-decoration: none; transition: 0.2s;}
        .btn-reset:hover { background: #e2e8f0; }

        /* Table Styling */
        .table-container { background: white; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); overflow: hidden; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 18px 24px; font-size: 13px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; background: var(--gray-light); border-bottom: 1px solid var(--gray-border); letter-spacing: 0.5px;}
        td { padding: 18px 24px; border-bottom: 1px solid var(--gray-border); color: #37474f; font-size: 14px; vertical-align: middle; }
        tr:hover td { background: #fdfdfd; }
        tr:last-child td { border-bottom: none; }

        /* Badges */
        .role-badge { padding: 5px 12px; border-radius: 8px; font-size: 11px; font-weight: 800; text-transform: uppercase; display: inline-block; border: 1px solid transparent;}
        .role-SUPER-ADMIN, .role-ADMIN { background: #ede9fe; color: #7c3aed; border-color: #ddd6fe; }
        .role-MANAGER { background: #dbeafe; color: #2563eb; border-color: #bfdbfe; }
        .role-AGENT { background: #d1fae5; color: #059669; border-color: #a7f3d0; }
        .role-BUYER { background: #f1f5f9; color: #475569; border-color: #e2e8f0; }

        /* Buttons */
        .btn-print { background: #e0f2fe; color: #0284c7; border: 1px solid #bae6fd; padding: 10px 20px; border-radius: 10px; font-size: 14px; font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; transition: 0.2s; cursor: pointer;}
        .btn-print:hover { background: #bae6fd; color: #0369a1; transform: translateY(-1px); }

        .btn-back { background: var(--primary-light); color: var(--primary); border: 1px solid var(--gray-border); padding: 10px 20px; border-radius: 10px; font-size: 14px; font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; transition: 0.2s; cursor: pointer; }
        .btn-back:hover { background: #c8e6c9; transform: translateY(-1px); }

        .log-date { font-weight: 700; color: #455a64; font-size: 14px;}
        .log-time { font-size: 12px; font-weight: 500; display: block; margin-top: 3px; color: var(--text-muted);}
        .action-text { font-weight: 800; color: var(--primary); font-size: 15px;}
        
        /* Print Styles */
        @media print {
            .top-header, .toolbar { display: none !important; }
            .main-panel { margin: 0; width: 100%; padding: 0; }
            .content-area { padding: 0; }
            .table-container { box-shadow: none; border: none; border-radius: 0; margin: 0; }
            th, td { border: 1px solid #cbd5e1; padding: 10px; }
            body { background: white; }
        }
    </style>
</head>
<body>

    <div class="main-panel">
        
        <div class="top-header">
            <div class="header-title">
                <h1>System Audit Logs</h1>
                <p>Full-screen tracking of activities and system modifications.</p>
            </div>
            
            <div style="display: flex; align-items: center; gap: 15px;">
                <a href="admin.php?view=dashboard" class="btn-back"><i class="fa-solid fa-arrow-left"></i> Back to Dashboard</a>
                <button onclick="window.print()" class="btn-print"><i class="fa-solid fa-print"></i> Print Logs</button>
                
                <div class="profile-dropdown" style="margin-left: 15px;">
                    <div class="profile-trigger">
                        <div class="profile-avatar">A</div>
                    </div>
                    <div class="dropdown-menu">
                        <a href="logout.php" class="dropdown-item text-danger"><i class="fa-solid fa-arrow-right-from-bracket"></i> Secure Logout</a>
                    </div>
                </div>
            </div>
        </div>

        <div class="content-area">

            <div class="toolbar">
                <form method="GET" style="display: flex; gap: 15px; flex-wrap: wrap; width: 100%; align-items: center;">
                    
                    <div style="flex: 1; position: relative; min-width: 300px;">
                        <i class="fa-solid fa-search" style="position: absolute; left: 16px; top: 14px; color: #94a3b8; font-size: 15px;"></i>
                        <input type="text" name="search" class="form-control" placeholder="Search by user name, action, or specific details..." value="<?= htmlspecialchars($search) ?>" style="padding-left: 42px; width: 100%;">
                    </div>
                    
                    <div>
                        <select name="sort" class="form-control" style="font-weight: 600; min-width: 160px;">
                            <option value="desc" <?= $sort == 'desc' ? 'selected' : '' ?>>Newest Logs First</option>
                            <option value="asc" <?= $sort == 'asc' ? 'selected' : '' ?>>Oldest Logs First</option>
                        </select>
                    </div>
                    
                    <div style="display: flex; gap: 10px;">
                        <button type="submit" class="btn-filter"><i class="fa-solid fa-filter"></i> Apply Filter</button>
                        <a href="audit_logs.php" class="btn-reset">Reset</a>
                    </div>

                </form>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 15%;">Date & Time</th>
                            <th style="width: 25%;">User Account</th>
                            <th style="width: 20%;">Action Performed</th>
                            <th style="width: 40%;">Activity Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php 
                        if($logs && $logs->num_rows > 0):
                            while($row = $logs->fetch_assoc()): 
                        ?>
                        <tr>
                            <td>
                                <span class="log-date"><?= date('M d, Y', strtotime($row['created_at'])) ?></span>
                                <span class="log-time"><?= date('h:i A', strtotime($row['created_at'])) ?></span>
                            </td>
                            <td>
                                <strong style="color: #1e293b; display: block; font-size: 15px; margin-bottom: 5px;"><?= htmlspecialchars($row['fullname'] ?? 'System Process') ?></strong>
                                <span class="role-badge role-<?= str_replace(' ', '-', $row['role'] ?? 'BUYER') ?>"><?= $row['role'] ?? 'SYSTEM' ?></span>
                            </td>
                            <td>
                                <span class="action-text"><?= htmlspecialchars($row['action']) ?></span>
                            </td>
                            <td style="font-size: 14px; color: #475569; line-height: 1.6; padding-right: 20px;">
                                <?= htmlspecialchars($row['details']) ?>
                            </td>
                        </tr>
                        <?php 
                            endwhile; 
                        else:
                        ?>
                        <tr>
                            <td colspan="4" style="text-align: center; padding: 60px; color: #94a3b8;">
                                <i class="fa-solid fa-clipboard-list" style="font-size: 40px; margin-bottom: 15px; display: block; opacity: 0.3;"></i>
                                <span style="font-weight: 500; font-size: 16px;">No activity logs found matching your criteria.</span>
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