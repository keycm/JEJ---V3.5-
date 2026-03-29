<?php
// master_list.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    header("Location: login.php");
    exit();
}

$alert_msg = "";
$alert_type = "";

// --- 1. HANDLE NEW MAP IMAGE UPLOAD ---
if(isset($_POST['upload_map']) && isset($_FILES['map_image']) && $_FILES['map_image']['error'] == 0){
    $target_dir = "uploads/";
    if(!is_dir($target_dir)) mkdir($target_dir);
    
    // Get file extension and force a specific name to overwrite the old one
    $ext = pathinfo($_FILES['map_image']['name'], PATHINFO_EXTENSION);
    $mapPath = $target_dir . "master_scheme_map." . $ext;
    
    // Delete existing map variations to prevent conflicts
    @unlink($target_dir . "master_scheme_map.png");
    @unlink($target_dir . "master_scheme_map.jpg");
    @unlink($target_dir . "master_scheme_map.jpeg");

    if(move_uploaded_file($_FILES['map_image']['tmp_name'], $mapPath)){
        $alert_msg = "New Scheme Map uploaded successfully!";
        $alert_type = "success";
    } else {
        $alert_msg = "Failed to upload the map image.";
        $alert_type = "error";
    }
}

// Determine which map image to show (Checks uploads folder first, falls back to default)
$current_map = "assets/map.png"; 
if(file_exists("uploads/master_scheme_map.png")) $current_map = "uploads/master_scheme_map.png";
elseif(file_exists("uploads/master_scheme_map.jpg")) $current_map = "uploads/master_scheme_map.jpg";
elseif(file_exists("uploads/master_scheme_map.jpeg")) $current_map = "uploads/master_scheme_map.jpeg";
// --------------------------------------


$lots = [];
$statusCounts = [
    'AVAILABLE' => 0,
    'SOLD' => 0,
    'RESERVED' => 0
];

// Fetch all lots
$sql = "SELECT * FROM lots ORDER BY CAST(block_no AS UNSIGNED), CAST(lot_no AS UNSIGNED)";
$result = $conn->query($sql);

if ($result && $result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $lots[] = $row;
        $status = strtoupper($row['status']);
        if (isset($statusCounts[$status])) {
            $statusCounts[$status]++;
        }
    }
}
$totalLots = count($lots);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Master List & Map | JEJ Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <style>
        :root {
            /* NATURE GREEN THEME */
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

        /* Stats Grid */
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 25px; }
        .stat-card { background: white; padding: 20px; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); display: flex; flex-direction: column; transition: transform 0.2s;}
        .stat-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
        .stat-card span { font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 5px; letter-spacing: 0.5px;}
        .stat-card strong { font-size: 28px; font-weight: 800; color: var(--dark); }
        
        .sc-total { border-top: 4px solid #3b82f6; } /* Vibrant Blue */
        .sc-avail { border-top: 4px solid #10b981; } /* Vibrant Emerald */
        .sc-res   { border-top: 4px solid #f59e0b; } /* Vibrant Amber */
        .sc-sold  { border-top: 4px solid #ef4444; } /* Vibrant Red */

        /* Map UI Styling */
        .map-container { background: white; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); padding: 20px; margin-bottom: 30px; }
        .map-toolbar { display: flex; gap: 10px; margin-bottom: 15px; align-items: center; flex-wrap: wrap; justify-content: space-between; }
        .map-toolbar-left { display: flex; gap: 10px; align-items: center; flex: 1; }
        .map-toolbar input[type="text"], .map-toolbar select, .map-toolbar button { padding: 10px 15px; border-radius: 8px; border: 1px solid #cbd5e1; font-family: inherit; font-size: 13px; outline: none; transition: 0.2s;}
        .map-toolbar input[type="text"]:focus, .map-toolbar select:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.15); }
        .map-toolbar input[type="text"] { min-width: 220px; }
        .map-toolbar button { background: var(--gray-light); color: var(--primary); border: 1px solid var(--gray-border); font-weight: 600; cursor: pointer; }
        .map-toolbar button:hover { background: var(--primary-light); }
        
        .legend { display: flex; gap: 15px; font-size: 12px; font-weight: 600; color: #455a64; margin-bottom: 15px;}
        .legend span { display: flex; align-items: center; gap: 5px; }
        .legend i { width: 14px; height: 14px; border-radius: 3px; border: 1px solid rgba(0,0,0,0.1); }

        .map-wrapper { width: 100%; overflow: auto; border-radius: 12px; border: 1px solid var(--gray-border); background: #f8fafc; position: relative; }
        #schemeMap { width: 100%; min-width: 1000px; display: block; }
        
        /* Interactive Polygon Styling (Vibrant Semantic) */
        .lot { stroke: #ffffff; stroke-width: 1.5; cursor: pointer; transition: all 0.3s ease; }
        .lot:hover { stroke: #1e293b; stroke-width: 3; filter: brightness(1.1); }
        .lot.available { fill: rgba(16, 185, 129, 0.6); } /* Emerald */
        .lot.reserved { fill: rgba(245, 158, 11, 0.6); }   /* Amber */
        .lot.sold { fill: rgba(239, 68, 68, 0.85); stroke: #991b1b; } /* Red */
        .lot.hidden-by-filter { opacity: 0; pointer-events: none; }
        
        /* Pinpoint Locate Highlight Styling */
        .lot.lot-dimmed { opacity: 0.15 !important; pointer-events: none; }
        .lot.lot-focused { 
            stroke: #3b82f6 !important; 
            stroke-width: 6 !important; 
            animation: pulseLot 1.5s infinite; 
            z-index: 100;
        }
        @keyframes pulseLot {
            0% { filter: drop-shadow(0 0 2px #3b82f6) brightness(1); }
            50% { filter: drop-shadow(0 0 15px #3b82f6) brightness(1.5); }
            100% { filter: drop-shadow(0 0 2px #3b82f6) brightness(1); }
        }

        /* Table Styling */
        .table-container { background: white; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); overflow: hidden; }
        .table-header { padding: 20px 24px; border-bottom: 1px solid var(--gray-border); display: flex; justify-content: space-between; align-items: center; background: #fff;}
        .table-title { font-size: 16px; font-weight: 700; color: var(--dark); }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px 24px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; background: var(--gray-light); border-bottom: 1px solid var(--gray-border); letter-spacing: 0.5px;}
        td { padding: 16px 24px; border-bottom: 1px solid var(--gray-border); color: #37474f; font-size: 14px; vertical-align: middle; }
        tr:hover td { background: #fdfdfd; }
        
        /* Badges & Buttons (Vibrant Semantic) */
        .status-badge { padding: 6px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; letter-spacing: 0.3px; display: inline-block;}
        
        .btn-action { padding: 8px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; text-decoration: none; display: inline-flex; align-items: center; gap: 5px; cursor: pointer; border: none; transition: 0.2s;}
        .btn-locate { background: #e0f2fe; color: #0284c7; border: 1px solid #bae6fd;} /* Sky Blue */
        .btn-locate:hover { background: #bae6fd; color: #0369a1; }
        
        .btn-edit { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1;} /* Slate */
        .btn-edit:hover { background: #e2e8f0; color: #334155; }
        
        .btn-full-edit { background: #ffffff; color: #64748b; border: 1px solid #cbd5e1; }
        .btn-full-edit:hover { background: #f8fafc; color: #475569; border-color: #94a3b8; }
        
        /* Modal & Form Styling */
        .modal { display: none; position: fixed; z-index: 9999; inset: 0; background: rgba(0, 0, 0, 0.6); backdrop-filter: blur(3px); padding: 30px; overflow-y: auto; }
        .modal-content { max-width: 550px; margin: 5vh auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        .modal-header { padding: 20px 25px; border-bottom: 1px solid var(--gray-border); display: flex; justify-content: space-between; align-items: center; background: var(--gray-light); }
        .modal-header h2 { margin: 0; font-size: 18px; font-weight: 700; color: var(--dark); }
        .close-btn { background: none; border: none; font-size: 20px; color: #90a4ae; cursor: pointer; transition: 0.2s;}
        .close-btn:hover { color: #ef4444; transform: scale(1.1);}
        #modalBody { padding: 25px; }

        /* Alert Styling */
        .alert-box { padding: 16px 20px; border-radius: 10px; margin-bottom: 25px; font-weight: 500; font-size: 14px; box-shadow: var(--shadow-sm); }
        .alert-success { background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; }
        .alert-error { background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }
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
            <a href="master_list.php" class="menu-link active"><i class="fa-solid fa-map-location-dot"></i> Master List / Map</a>
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
                <h1>Master List & Scheme Map</h1>
                <p>Interactive subdivision map and complete property inventory.</p>
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
                <div class="alert-box <?= $alert_type == 'success' ? 'alert-success' : 'alert-error' ?>">
                    <i class="fa-solid <?= $alert_type == 'success' ? 'fa-check-circle' : 'fa-exclamation-circle' ?>" style="margin-right: 8px;"></i>
                    <?= $alert_msg ?>
                </div>
            <?php endif; ?>

            <div class="stats-grid">
                <div class="stat-card sc-total">
                    <span>Total Lots</span>
                    <strong><?= $totalLots ?></strong>
                </div>
                <div class="stat-card sc-avail">
                    <span>Available</span>
                    <strong><?= $statusCounts['AVAILABLE'] ?></strong>
                </div>
                <div class="stat-card sc-res">
                    <span>Reserved</span>
                    <strong><?= $statusCounts['RESERVED'] ?></strong>
                </div>
                <div class="stat-card sc-sold">
                    <span>Sold</span>
                    <strong><?= $statusCounts['SOLD'] ?></strong>
                </div>
            </div>

            <div class="map-container">
                <div class="map-toolbar">
                    <div class="map-toolbar-left">
                        <i class="fa-solid fa-search" style="color: #90a4ae; margin-left: 5px;"></i>
                        <input type="text" id="searchLot" placeholder="Search by Block or Lot No...">
                        <select id="filterStatus">
                            <option value="">All Statuses</option>
                            <option value="available">Available</option>
                            <option value="reserved">Reserved</option>
                            <option value="sold">Sold</option>
                        </select>
                        <button type="button" onclick="resetFilters()"><i class="fa-solid fa-rotate-right"></i> Reset Search</button>
                    </div>
                    
                    <form method="POST" enctype="multipart/form-data" style="display:flex; gap:10px; align-items:center; background: #f8fafc; padding: 6px 15px; border-radius: 8px; border: 1px solid #e2e8f0;">
                        <span style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase;">Map Background:</span>
                        <input type="file" name="map_image" accept="image/*" required style="font-size: 12px; max-width: 180px;">
                        <button type="submit" name="upload_map" style="background: #334155; color: white; border: none; padding: 6px 12px; font-size: 12px; border-radius: 6px; cursor: pointer; font-weight: 600;"><i class="fa-solid fa-upload"></i> Upload</button>
                    </form>
                </div>

                <div class="legend">
                    <span><i style="background: rgba(16, 185, 129, 0.8);"></i> Available</span>
                    <span><i style="background: rgba(245, 158, 11, 0.8);"></i> Reserved</span>
                    <span><i style="background: rgba(239, 68, 68, 0.9);"></i> Sold</span>
                </div>

                <div class="map-wrapper" id="svgWrapper">
                    <svg id="schemeMap" viewBox="0 0 1464 1052" preserveAspectRatio="xMidYMid meet">
                        <image href="<?= $current_map ?>?v=<?= time() ?>" x="0" y="0" width="1464" height="1052"></image>

                        <?php foreach ($lots as $lot): ?>
                            <?php
                                $statusClass = strtolower($lot['status']);
                                $dataBlock = htmlspecialchars($lot['block_no']);
                                $dataLot = htmlspecialchars($lot['lot_no']);
                                $dataStatus = htmlspecialchars($lot['status']);
                                $dataId = (int)$lot['id'];
                                $points = isset($lot['coordinates']) ? htmlspecialchars($lot['coordinates']) : ''; 
                            ?>
                            <?php if(!empty($points)): ?>
                            <polygon
                                class="lot <?= $statusClass ?>"
                                points="<?= $points ?>"
                                data-id="<?= $dataId ?>"
                                data-block="<?= $dataBlock ?>"
                                data-lot="<?= $dataLot ?>"
                                data-status="<?= $dataStatus ?>"
                                onclick="openLotDetails(<?= $dataId ?>)"
                            >
                                <title>Block <?= $dataBlock ?> - Lot <?= $dataLot ?> (<?= $dataStatus ?>)</title>
                            </polygon>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </svg>
                </div>
            </div>

            <div class="table-container">
                <div class="table-header">
                    <span class="table-title"><i class="fa-solid fa-list" style="color: var(--primary); margin-right: 8px;"></i> Master List Directory</span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Image</th>
                            <th>Location</th>
                            <th>Block/Lot</th>
                            <th>Area</th>
                            <th>Price</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="masterTableBody">
                        <?php foreach($lots as $lot): ?>
                        <tr class="lot-row" data-block="<?= strtolower($lot['block_no']) ?>" data-lot="<?= strtolower($lot['lot_no']) ?>" data-status="<?= strtolower($lot['status']) ?>">
                            <td><img src="uploads/<?= $lot['lot_image']?:'default_lot.jpg' ?>" style="width: 45px; height: 45px; object-fit: cover; border-radius: 8px; border: 1px solid var(--gray-border);"></td>
                            <td>
                                <strong style="color: #1e293b;"><?= $lot['location'] ?? 'N/A' ?></strong>
                                <div style="font-size: 11px; color: #64748b; margin-top: 2px;"><?= $lot['property_type'] ?></div>
                            </td>
                            <td style="font-weight: 700; color: var(--primary);">B-<?= $lot['block_no'] ?> L-<?= $lot['lot_no'] ?></td>
                            <td><?= $lot['area'] ?> sqm</td>
                            <td style="font-weight: 600; color: #1e293b;">₱<?= number_format($lot['total_price']) ?></td>
                            <td>
                                <?php 
                                    // Semantic Badges
                                    $badges = [
                                        'AVAILABLE' => ['bg'=>'#d1fae5', 'col'=>'#065f46'], // Emerald
                                        'RESERVED'  => ['bg'=>'#fef3c7', 'col'=>'#92400e'], // Amber
                                        'SOLD'      => ['bg'=>'#fee2e2', 'col'=>'#991b1b']  // Red
                                    ];
                                    $b = $badges[strtoupper($lot['status'])] ?? ['bg'=>'#f1f5f9', 'col'=>'#475569'];
                                ?>
                                <span class="status-badge" style="background: <?= $b['bg'] ?>; color: <?= $b['col'] ?>;"><?= strtoupper($lot['status']) ?></span>
                            </td>
                            <td>
                                <button type="button" class="btn-action btn-locate" onclick="locateLot(<?= $lot['id'] ?>)"><i class="fa-solid fa-location-dot"></i> Locate</button>
                                <button type="button" class="btn-action btn-edit" onclick="openLotDetails(<?= $lot['id'] ?>)"><i class="fa-solid fa-pen"></i> Quick Edit</button>
                                <a href="admin.php?view=inventory&edit_id=<?= $lot['id'] ?>" class="btn-action btn-full-edit"><i class="fa-solid fa-gear"></i> Full Edit</a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
        </div>
    </div>

    <div id="lotModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Quick Edit Property</h2>
                <button class="close-btn" onclick="closeModal()"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div id="modalBody">
                <p>Loading...</p>
            </div>
        </div>
    </div>

    <script>
        const modal = document.getElementById('lotModal');
        const modalBody = document.getElementById('modalBody');

        // --- 1. PINPOINT/LOCATE LOT ON MAP ---
        function locateLot(id) {
            // Scroll smoothly to the map
            document.getElementById('svgWrapper').scrollIntoView({ behavior: 'smooth', block: 'center' });

            // Highlight the specific lot and dim others
            document.querySelectorAll('polygon.lot').forEach(lot => {
                if(parseInt(lot.dataset.id) === parseInt(id)) {
                    lot.classList.remove('hidden-by-filter');
                    lot.classList.remove('lot-dimmed');
                    lot.classList.add('lot-focused');
                } else {
                    lot.classList.remove('lot-focused');
                    lot.classList.add('lot-dimmed');
                }
            });

            // Show a "Clear Focus" button in the toolbar if it's not already there
            let resetBtn = document.getElementById('clearFocusBtn');
            if(!resetBtn) {
                resetBtn = document.createElement('button');
                resetBtn.id = 'clearFocusBtn';
                resetBtn.type = 'button';
                resetBtn.innerHTML = '<i class="fa-solid fa-eye-slash"></i> Clear Map Focus';
                resetBtn.style.cssText = "background: #ef4444; color: white; border: none; padding: 10px 15px; border-radius: 8px; font-weight: 600; cursor: pointer; margin-left: 10px; animation: pulseLot 1.5s infinite;";
                resetBtn.onclick = function() {
                    restoreMapVisibility();
                };
                document.querySelector('.map-toolbar-left').appendChild(resetBtn);
            }
        }


        // --- 2. OPEN MODAL & ISOLATE POLYGON ---
        function openLotDetails(id) {
            if (isDrawing) return; 

            // Trigger the same visual highlighting as the locate button
            locateLot(id);

            modal.style.display = 'block';
            modalBody.innerHTML = '<p style="text-align:center; color:#64748b; padding: 20px;"><i class="fa-solid fa-spinner fa-spin"></i> Loading data...</p>';

            // Load the edit form from get_lot.php
            fetch('get_lot.php?id=' + encodeURIComponent(id))
                .then(response => response.text())
                .then(html => { modalBody.innerHTML = html; })
                .catch(() => { modalBody.innerHTML = '<p style="color:#ef4444; text-align:center; padding: 20px;">Failed to load data. Please check your connection.</p>'; });
        }

        // Close modal and restore visibility to all lots
        function closeModal() { 
            modal.style.display = 'none'; 
            restoreMapVisibility();
        }

        function restoreMapVisibility() {
            document.querySelectorAll('polygon.lot').forEach(lot => {
                lot.classList.remove('hidden-by-filter');
                lot.classList.remove('lot-focused');
                lot.classList.remove('lot-dimmed');
            });
            applyFilters(); // Re-apply search filters if any were typed
            
            // Remove the clear focus button
            let resetBtn = document.getElementById('clearFocusBtn');
            if(resetBtn) resetBtn.remove();
        }

        window.onclick = function(event) { 
            if (event.target === modal) closeModal(); 
        };


        // --- 3. AJAX FORM SUBMISSION (Save changes without reloading) ---
        function saveLot(event) {
            event.preventDefault(); 

            const form = document.getElementById('lotForm');
            const formData = new FormData(form);
            
            let saveResult = document.getElementById('saveResult');
            if (!saveResult) {
                saveResult = document.createElement('div');
                saveResult.id = 'saveResult';
                saveResult.style.marginTop = '15px';
                saveResult.style.textAlign = 'center';
                form.appendChild(saveResult);
            }

            saveResult.innerHTML = '<p style="color:#3b82f6; font-size:14px; font-weight:600;"><i class="fa-solid fa-spinner fa-spin"></i> Saving changes...</p>';

            // Post to save_lot.php
            fetch('save_lot.php', { method: 'POST', body: formData })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    saveResult.innerHTML = '<p style="color:#10b981; font-weight:600; font-size:14px;"><i class="fa-solid fa-check-circle"></i> ' + data.message + '</p>';
                    setTimeout(() => { location.reload(); }, 800);
                } else {
                    saveResult.innerHTML = '<p style="color:#ef4444; font-weight:600; font-size:14px;"><i class="fa-solid fa-circle-exclamation"></i> ' + data.message + '</p>';
                }
            })
            .catch(() => {
                saveResult.innerHTML = '<p style="color:#ef4444; font-weight:600; font-size:14px;"><i class="fa-solid fa-circle-exclamation"></i> Server communication error.</p>';
            });
        }


        // --- 4. INTERACTIVE MAP PINNING TOOL ---
        let isDrawing = false;
        let tempPoints = [];
        let tempPolygon = null;

        function startDrawing() {
            modal.style.display = 'none'; 
            isDrawing = true;
            tempPoints = [];
            
            // Show drawing instruction banner
            let banner = document.getElementById('drawBanner');
            if(!banner) {
                banner = document.createElement('div');
                banner.id = 'drawBanner';
                banner.innerHTML = `
                    <div style="display:flex; align-items:center; gap:15px;">
                        <span><i class="fa-solid fa-pen-ruler"></i> <strong>Map Pin Mode:</strong> Click the corners of the lot on the map to draw its shape.</span>
                        <button onclick="finishDrawing()" style="background: #10b981; color: white; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size:13px; transition: 0.2s;">Done</button> 
                        <button onclick="cancelDrawing()" style="background: #ef4444; color: white; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size:13px; transition: 0.2s;">Cancel</button>
                    </div>
                `;
                banner.style.cssText = "position: fixed; top: 20px; left: 50%; transform: translateX(-50%); background: #1e293b; color: white; padding: 15px 25px; border-radius: 12px; z-index: 10000; box-shadow: 0 10px 25px rgba(0,0,0,0.3); font-size: 14px;";
                document.body.appendChild(banner);
            }
            banner.style.display = 'block';

            // Create temporary polygon
            const svg = document.getElementById('schemeMap');
            tempPolygon = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
            tempPolygon.setAttribute('fill', 'rgba(245, 158, 11, 0.6)'); 
            tempPolygon.setAttribute('stroke', '#d97706');
            tempPolygon.setAttribute('stroke-width', '4');
            svg.appendChild(tempPolygon);
            
            // Scroll user smoothly to the map
            document.getElementById('svgWrapper').scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        // SVG Click listener to plot points
        document.getElementById('schemeMap').addEventListener('click', function(e) {
            if(!isDrawing) return;
            
            const svg = document.getElementById('schemeMap');
            let pt = svg.createSVGPoint();
            pt.x = e.clientX;
            pt.y = e.clientY;
            
            // Convert screen coordinates to exact SVG map coordinates
            let svgP = pt.matrixTransform(svg.getScreenCTM().inverse());
            
            let x = Math.round(svgP.x * 10) / 10;
            let y = Math.round(svgP.y * 10) / 10;
            
            tempPoints.push(`${x},${y}`);
            tempPolygon.setAttribute('points', tempPoints.join(' '));
        });

        function finishDrawing() {
            isDrawing = false;
            document.getElementById('drawBanner').style.display = 'none';
            modal.style.display = 'block'; 
            
            if(tempPoints.length > 2) {
                // Find the points textarea and fill it
                let pointsInput = document.getElementById('polygonPoints');
                if(pointsInput) pointsInput.value = tempPoints.join(' ');
            } else {
                alert("Please click at least 3 points on the map to create a valid shape.");
            }
            if(tempPolygon) tempPolygon.remove();
        }

        function cancelDrawing() {
            isDrawing = false;
            document.getElementById('drawBanner').style.display = 'none';
            modal.style.display = 'block';
            if(tempPolygon) tempPolygon.remove();
        }


        // --- 5. SEARCH & FILTER LOGIC (Filters map & table simultaneously) ---
        function applyFilters() {
            const searchValue = document.getElementById('searchLot').value.trim().toLowerCase();
            const statusValue = document.getElementById('filterStatus').value.trim().toLowerCase();

            // Filter Map Polygons
            document.querySelectorAll('polygon.lot').forEach(lot => {
                const block = (lot.dataset.block || '').toLowerCase();
                const lotNo = (lot.dataset.lot || '').toLowerCase();
                const status = (lot.dataset.status || '').toLowerCase();

                const matchesSearch = searchValue === '' || block.includes(searchValue) || lotNo.includes(searchValue) || (`b-${block} l-${lotNo}`).includes(searchValue) || (`block ${block} lot ${lotNo}`).includes(searchValue);
                const matchesStatus = statusValue === '' || status === statusValue;

                if (matchesSearch && matchesStatus) {
                    // Only remove hidden filter if it's not currently dimmed by the locate function
                    if(!lot.classList.contains('lot-dimmed')) lot.classList.remove('hidden-by-filter');
                } else {
                    lot.classList.add('hidden-by-filter');
                }
            });

            // Filter Table Rows
            document.querySelectorAll('.lot-row').forEach(row => {
                const block = row.dataset.block;
                const lotNo = row.dataset.lot;
                const status = row.dataset.status;

                const matchesSearch = searchValue === '' || block.includes(searchValue) || lotNo.includes(searchValue) || (`b-${block} l-${lotNo}`).includes(searchValue);
                const matchesStatus = statusValue === '' || status === statusValue;

                if (matchesSearch && matchesStatus) row.style.display = '';
                else row.style.display = 'none';
            });
        }

        function resetFilters() {
            document.getElementById('searchLot').value = '';
            document.getElementById('filterStatus').value = '';
            restoreMapVisibility(); // Clear out all filters and focus
        }

        document.getElementById('searchLot').addEventListener('input', applyFilters);
        document.getElementById('filterStatus').addEventListener('change', applyFilters);
    </script>
</body>
</html>