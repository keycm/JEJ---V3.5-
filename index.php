<?php
// index.php
include 'config.php';

// --- SEARCH LOGIC ---
$where_clauses = ["1=1"];
$params = [];
$types = "";

// 1. Keyword Search
if(!empty($_GET['q'])){
    $q = "%" . $_GET['q'] . "%";
    $where_clauses[] = "(l.location LIKE ? OR p.name LIKE ? OR l.property_type LIKE ?)";
    $params[] = $q; $params[] = $q; $params[] = $q;
    $types .= "sss";
}

// 2. Status Filter
if(!empty($_GET['status']) && $_GET['status'] != 'ALL'){
    $where_clauses[] = "l.status = ?";
    $params[] = $_GET['status'];
    $types .= "s";
}

$where_sql = implode(" AND ", $where_clauses);

$query = "SELECT l.*, p.name as phase_name 
          FROM lots l 
          LEFT JOIN phases p ON l.phase_id = p.id 
          WHERE $where_sql 
          ORDER BY l.status = 'AVAILABLE' DESC, l.id DESC";

$stmt = $conn->prepare($query);
if(!empty($params)){
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JEJ Surveying Services | Find Your Dream Property</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@500;700;800;900&family=Open+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <link rel="stylesheet" href="assets/modern.css">
</head>
<body>

    <nav class="nav">
        <div class="brand-wrapper">
            <a href="index.php" style="display: flex; align-items: center; gap: 10px;">
                <img src="assets/logo.png" alt="JEJ Logo" style="height: 45px; width: auto; border-radius: 6px;">
                <span class="nav-brand">JEJ Surveying Services</span>
            </a>
        </div>
        
        <div class="nav-links desktop-only">
            <a href="index.php" class="active">Properties</a>
            <?php if(isset($_SESSION['user_id'])): ?>
                <?php if(in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])): ?>
                    <a href="admin.php">Admin Panel</a>
                <?php else: ?>
                    <a href="my_reservations.php">My Reservations</a>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <div class="user-menu">
            <?php if(isset($_SESSION['user_id'])): ?>
                <div style="display:flex; align-items:center; gap:12px;">
                    <div class="user-details">
                        <span class="user-name"><?= htmlspecialchars($_SESSION['fullname']) ?></span>
                        <span class="user-role"><?= $_SESSION['role'] ?></span>
                    </div>
                    <div class="avatar-circle">
                        <?= strtoupper(substr($_SESSION['fullname'], 0, 1)) ?>
                    </div>
                    <a href="logout.php" style="color: #E53E3E; margin-left:8px; font-size:16px;" title="Logout">
                        <i class="fa-solid fa-right-from-bracket"></i>
                    </a>
                </div>
            <?php else: ?>
                <a href="login.php" style="font-weight: 700; color: var(--dark); margin-right: 20px;">Login</a>
                <a href="register.php" class="search-btn" style="padding: 10px 25px; font-size: 13px; text-decoration: none; border-radius: 30px;">Get Started</a>
            <?php endif; ?>
        </div>
    </nav>

    <header class="hero">
        <h1>Find Your Realty</h1>
        <p>Discover sustainable lots and build your future home in nature.</p>
        
        <form class="search-box" method="GET" action="index.php">
            <div class="search-input-group">
                <i class="fa-solid fa-location-dot"></i>
                <input type="text" name="q" class="search-input" placeholder="Search location, phase, or block..." value="<?= htmlspecialchars($_GET['q'] ?? '') ?>">
            </div>
            
            <span class="divider-vertical"></span>

            <div class="search-input-group" style="min-width: 180px;">
                <i class="fa-solid fa-filter"></i>
                <select name="status" class="search-input" style="appearance: none; cursor: pointer;">
                    <option value="ALL">All Status</option>
                    <option value="AVAILABLE" <?= (($_GET['status']??'')=='AVAILABLE')?'selected':'' ?>>Available Only</option>
                    <option value="RESERVED" <?= (($_GET['status']??'')=='RESERVED')?'selected':'' ?>>Reserved</option>
                </select>
                </div>

            <button type="submit" class="search-btn">Search <i class="fa-solid fa-arrow-right" style="margin-left: 8px;"></i></button>
        </form>
    </header>

    <div class="container" id="results">
        
        <?php if(!empty($_GET['q'])): ?>
            <h2 class="section-title">Search Results for "<?= htmlspecialchars($_GET['q']) ?>"</h2>
        <?php else: ?>
            <h2 class="section-title">Latest Opportunities</h2>
        <?php endif; ?>

        <div class="property-grid">
            <?php if($result->num_rows > 0): ?>
                <?php while($row = $result->fetch_assoc()): 
                    $loc_display = !empty($row['location']) ? $row['location'] : ($row['phase_name'] ?? 'Unknown Location');
                ?>
                <a href="lot_details.php?id=<?= $row['id'] ?>" class="prop-card">
                    <div class="prop-img-box">
                        <img src="<?= $row['lot_image'] ? 'uploads/'.$row['lot_image'] : 'assets/default_lot.jpg' ?>" class="prop-img">
                        <span class="prop-badge badge-<?= $row['status'] ?>">
                            <?= $row['status'] == 'AVAILABLE' ? 'For Sale' : $row['status'] ?>
                        </span>
                    </div>
                    
                    <div class="prop-info">
                        <div class="prop-loc">
                            <i class="fa-solid fa-map-pin" style="color: var(--primary);"></i> <?= htmlspecialchars($loc_display) ?>
                        </div>
                        <h3 class="prop-title">Block <?= $row['block_no'] ?>, Lot <?= $row['lot_no'] ?> <br>
                            <span style="font-weight: 500; font-size: 14px; color: #718096;"><?= $row['property_type'] ?></span>
                        </h3>
                        
                        <div class="prop-stats">
                            <div class="prop-stat"><i class="fa-solid fa-ruler-combined"></i> <?= number_format($row['area']) ?> m²</div>
                            <div class="prop-stat"><i class="fa-solid fa-tag"></i> ₱<?= number_format($row['price_per_sqm']) ?>/sqm</div>
                        </div>

                        <div class="prop-price">
                            <div>₱<?= number_format($row['total_price']) ?></div>
                            <div class="btn-view" title="View Details">
                                <i class="fa-solid fa-arrow-right"></i>
                            </div>
                        </div>
                    </div>
                </a>
                <?php endwhile; ?>
            <?php else: ?>
                <div style="grid-column: 1/-1; text-align: center; padding: 60px; color: #A0AEC0; background: #fff; border-radius: 16px; box-shadow: var(--shadow-soft); border: 1px solid #EDF2F7;">
                    <i class="fa-solid fa-folder-open" style="font-size: 40px; margin-bottom: 20px; color: #CBD5E0;"></i>
                    <h3 style="color:#4A5568; margin-bottom: 5px;">No properties found</h3>
                    <p style="font-size: 14px;">We couldn't find any lots matching your search criteria.</p>
                    <a href="index.php" style="color: var(--primary); font-weight: 700; margin-top: 15px; display: inline-block; font-size: 14px;">Clear Filters</a>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <footer class="footer">
        <div style="margin-bottom: 25px;">
            <img src="assets/logo.png" alt="JEJ Logo" style="height: 60px; width: auto; border-radius: 8px; background: white; padding: 5px;">
        </div>
        <p><strong>JEJ Realty Services</strong></p>
        <p style="opacity:0.6; margin-top:10px; font-size: 14px;">Professional surveying and blueprint solutions.</p>
        <div style="margin-top: 40px; font-size: 12px; opacity: 0.4;">
            &copy; <?= date('Y') ?> All Rights Reserved.
        </div>
    </footer>
    
    <?php if(!empty($_GET['q']) || !empty($_GET['status'])): ?>
    <script>
        document.addEventListener("DOMContentLoaded", function() {
            var element = document.getElementById("results");
            if (element) {
                element.scrollIntoView({ behavior: 'smooth' });
            }
        });
    </script>
    <?php endif; ?>

</body>
</html>