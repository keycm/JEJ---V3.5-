<?php
// lot_details.php
include 'config.php';

if(!isset($_SESSION['user_id'])){ header("Location: login.php"); exit(); }
if(!isset($_GET['id'])){ header("Location: index.php"); exit(); }

$id = (int)$_GET['id'];

// Fetch Lot Details
$stmt = $conn->prepare("SELECT * FROM lots WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$lot = $stmt->get_result()->fetch_assoc();

if(!$lot) die("Property not found.");

// Fetch Gallery Images
$gallery_stmt = $conn->prepare("SELECT * FROM lot_gallery WHERE lot_id = ?");
$gallery_stmt->bind_param("i", $id);
$gallery_stmt->execute();
$gallery_res = $gallery_stmt->get_result();

// Build array of all images for the JS Gallery
$js_images = [];
// Add Main Image first
$main_img = $lot['lot_image'] ? 'uploads/'.$lot['lot_image'] : 'assets/default_lot.jpg';
$js_images[] = $main_img;

// Add Gallery Images
$gallery_html = ""; 
while($img = $gallery_res->fetch_assoc()){
    $path = 'uploads/'.$img['image_path'];
    $js_images[] = $path;
    $gallery_html .= '<div class="thumb-box" onclick="openLightbox(\''.$path.'\')"><img src="'.$path.'" class="thumb-img"></div>';
}

// --- FETCH DATA FOR SCHEME MAP ---
// Determine which map image to show
$current_map = "assets/map.png"; 
if(file_exists("uploads/master_scheme_map.png")) $current_map = "uploads/master_scheme_map.png";
elseif(file_exists("uploads/master_scheme_map.jpg")) $current_map = "uploads/master_scheme_map.jpg";
elseif(file_exists("uploads/master_scheme_map.jpeg")) $current_map = "uploads/master_scheme_map.jpeg";

// Fetch all lots to render the subdivision context
$all_lots = [];
$res_lots = $conn->query("SELECT id, block_no, lot_no, status, coordinates FROM lots");
if($res_lots && $res_lots->num_rows > 0){
    while($r = $res_lots->fetch_assoc()){
        $all_lots[] = $r;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Property Details | JEJ Surveying Services</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />

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

        body { background-color: #fafcf9; font-family: 'Inter', sans-serif; color: #37474f; margin: 0; padding: 0; overflow-x: hidden;}

        /* --- NAVIGATION --- */
        .nav { display: flex; justify-content: space-between; align-items: center; padding: 15px 5%; background: white; border-bottom: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); position: sticky; top: 0; z-index: 1000; }
        .nav-left { display: flex; align-items: center; }
        .brand-wrapper { display: flex; align-items: center; text-decoration: none; }
        .nav-brand { font-size: 18px; font-weight: 800; color: var(--primary); letter-spacing: -0.5px; }
        
        .nav-links { display: flex; gap: 20px; align-items: center; }
        .nav-links a { color: #455a64; text-decoration: none; font-weight: 600; font-size: 14px; transition: 0.2s; }
        .nav-links a:hover { color: var(--primary); }
        
        .user-menu { display: flex; align-items: center; gap: 15px; font-size: 14px; font-weight: 600; color: #37474f;}

        /* General Page Layout */
        .main-content { padding: 0 5% 50px 5%; max-width: 1400px; margin: 0 auto; }
        .breadcrumb { margin: 30px 0 20px; font-size: 13px; color: #94a3b8; display: flex; align-items: center; gap: 10px; font-weight: 500;}
        .breadcrumb a { color: var(--primary); text-decoration: none; font-weight: 600; transition: 0.2s;}
        .breadcrumb a:hover { color: var(--dark); }

        /* --- MEDIA & ACTION GRID (Top Section) --- */
        .media-action-grid { display: grid; grid-template-columns: 1.2fr 1fr; gap: 30px; align-items: start; margin-bottom: 30px;}

        /* Image Gallery */
        .main-img-box { position: relative; border-radius: 12px; overflow: hidden; height: 400px; box-shadow: var(--shadow-sm); background: #f8fafc; cursor: pointer; border: 1px solid var(--gray-border);}
        .main-img { width: 100%; height: 100%; object-fit: cover; transition: transform 0.4s ease; }
        .main-img-box:hover .main-img { transform: scale(1.03); }
        
        .badge { position: absolute; padding: 6px 14px; border-radius: 8px; font-size: 12px; font-weight: 800; text-transform: uppercase; box-shadow: 0 4px 6px rgba(0,0,0,0.1); letter-spacing: 0.5px;}
        .badge.AVAILABLE { background: #10b981; color: white; }
        .badge.RESERVED { background: #f59e0b; color: white; }
        .badge.SOLD { background: #ef4444; color: white; }

        .gallery-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-top: 15px; margin-bottom: 25px; }
        .thumb-box { height: 70px; border-radius: 8px; overflow: hidden; cursor: pointer; border: 2px solid transparent; opacity: 0.7; transition: 0.2s; box-shadow: var(--shadow-sm);}
        .thumb-box:hover { border-color: var(--primary); opacity: 1; transform: translateY(-3px);}
        .thumb-img { width: 100%; height: 100%; object-fit: cover; }

        /* --- PROPERTY DETAILS CARD --- */
        .specs-card { background: white; border-radius: 12px; padding: 25px 30px; box-shadow: var(--shadow-sm); border: 1px solid var(--gray-border); }
        .specs-card .prop-type { font-size: 11px; font-weight: 800; color: var(--primary); text-transform: uppercase; letter-spacing: 1px; background: var(--primary-light); padding: 4px 10px; border-radius: 6px; display: inline-block; margin-bottom: 10px;}
        .specs-card h2 { font-size: 28px; font-weight: 800; color: #0f172a; margin: 0 0 5px; letter-spacing: -0.5px; line-height: 1.2;}
        .specs-card .location { color: #64748b; font-size: 14px; font-weight: 500; margin-bottom: 20px; display: flex; align-items: center; gap: 6px; }
        
        .price-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; background: #f8fafc; padding: 15px 20px; border-radius: 10px; border: 1px solid #e2e8f0; margin-bottom: 20px; }
        .price-grid div small { display: block; font-size: 11px; color: #64748b; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;}
        .price-grid div strong { font-size: 16px; color: #1e293b; font-weight: 800; }
        .price-grid .total-row { grid-column: 1 / -1; border-top: 1px dashed #cbd5e1; padding-top: 12px; margin-top: 5px; }
        .price-grid .total-row strong { font-size: 22px; color: var(--primary); font-weight: 900; letter-spacing: -0.5px;}

        .specs-card h4 { font-size: 15px; font-weight: 800; color: #1e293b; margin: 0 0 8px; }
        .specs-card p { font-size: 14px; color: #475569; line-height: 1.6; margin: 0; }

        /* Reservation Form */
        .form-card { background: white; border-radius: 12px; padding: 0; box-shadow: var(--shadow-sm); border: 1px solid var(--gray-border); display: flex; flex-direction: column; overflow: hidden; height: fit-content; }
        .form-header { padding: 25px 30px 15px; background: white; border-bottom: 1px solid #f1f5f9;}
        .form-body { padding: 20px 30px 30px; }

        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 6px; }
        .form-control { width: 100%; padding: 10px 14px; border-radius: 8px; border: 1px solid #cbd5e1; background: #f8fafc; font-size: 13px; font-family: inherit; transition: 0.2s; box-sizing: border-box; outline: none;}
        .form-control:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.15); background: white;}
        
        .btn-submit { width: 100%; background: var(--primary); color: white; border: none; padding: 16px; border-radius: 10px; font-weight: 800; font-size: 15px; cursor: pointer; margin-top: 10px; transition: 0.2s; box-shadow: 0 4px 6px rgba(46, 125, 50, 0.2); letter-spacing: 0.5px;}
        .btn-submit:hover { background: var(--dark); transform: translateY(-2px); box-shadow: 0 6px 12px rgba(27, 94, 32, 0.3);}

        /* --- MAPS GRID (Scheme + Geo Map Side by Side on Bottom) --- */
        .maps-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 30px; margin-top: 20px; }
        
        .map-wrapper { display: flex; flex-direction: column; width: 100%; border-radius: 12px; border: 1px solid var(--gray-border); background: #ffffff; overflow: hidden; box-shadow: var(--shadow-sm); position: relative; transition: all 0.3s ease; height: 600px; }
        
        /* FULLSCREEN MODIFIER for Scheme Map */
        .map-wrapper.fullscreen { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: 9999; border-radius: 0; margin: 0; border: none; }

        .map-header { padding: 15px 20px; background: white; border-bottom: 1px solid var(--gray-border); font-size: 15px; font-weight: 800; color: var(--dark); display: flex; align-items: center; justify-content: space-between; flex-shrink: 0;}
        
        /* Scheme Map specifics */
        .svg-container { flex: 1; width: 100%; position: relative; background: #ffffff; overflow: hidden; cursor: grab; }
        .svg-container:active { cursor: grabbing; }
        #schemeMap { width: 100%; height: 100%; transform-origin: center center; display: block; transition: transform 0.05s linear;}
        
        .map-controls-overlay { position: absolute; right: 20px; top: 50%; transform: translateY(-50%); display: flex; flex-direction: column; gap: 5px; z-index: 100; background: white; border-radius: 8px; border: 1px solid #cbd5e1; overflow: hidden; box-shadow: var(--shadow-sm); }
        .zoom-btn { background: transparent; color: #475569; border: none; width: 40px; height: 40px; font-size: 15px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: 0.2s; border-bottom: 1px solid #f1f5f9; }
        .zoom-btn:last-child { border-bottom: none; }
        .zoom-btn:hover { background: var(--primary-light); color: var(--primary); }

        /* Geo Map specifics */
        #map-display { flex: 1; width: 100%; z-index: 1; background: #e2e8f0; height: 100%;}

        /* --- HIGH VISIBILITY MAP LOT HIGHLIGHTING --- */
        .lot { transition: all 0.3s ease; }
        .lot.available { fill: rgba(34, 197, 94, 0.7); stroke: #15803d; stroke-width: 2; } /* Vibrant Green */
        .lot.reserved { fill: rgba(234, 179, 8, 0.7); stroke: #a16207; stroke-width: 2; } /* Vibrant Yellow */
        .lot.sold { fill: rgba(239, 68, 68, 0.85); stroke: #991b1b; stroke-width: 2; } /* Vibrant Red */
        
        .lot-dimmed { opacity: 0.35; pointer-events: none; } 
        .lot-focused { 
            stroke: #00e5ff !important; 
            stroke-width: 7 !important; 
            fill: rgba(0, 229, 255, 0.5) !important; /* Neon Cyan Fill */
            animation: pulseLot 1.5s infinite; 
            z-index: 100; 
            opacity: 1 !important; 
        }
        @keyframes pulseLot {
            0% { filter: drop-shadow(0 0 5px #00e5ff) brightness(1); }
            50% { filter: drop-shadow(0 0 25px #00e5ff) brightness(1.4); }
            100% { filter: drop-shadow(0 0 5px #00e5ff) brightness(1); }
        }

        /* Lightbox */
        .lightbox { display: none; position: fixed; z-index: 2000; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15, 23, 42, 0.95); backdrop-filter: blur(5px); justify-content: center; align-items: center; flex-direction: column; }
        .lightbox img { max-width: 90%; max-height: 85vh; border-radius: 8px; box-shadow: 0 10px 40px rgba(0,0,0,0.5); user-select: none; }
        .lb-controls { position: absolute; top: 50%; width: 100%; display: flex; justify-content: space-between; padding: 0 40px; transform: translateY(-50%); pointer-events: none; }
        .lb-btn { pointer-events: auto; background: rgba(255,255,255,0.1); color: white; border: 1px solid rgba(255,255,255,0.2); width: 50px; height: 50px; border-radius: 50%; font-size: 20px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: 0.2s; backdrop-filter: blur(5px); }
        .lb-btn:hover { background: var(--primary); border-color: var(--primary); transform: scale(1.1); }
        .close-btn { position: absolute; top: 25px; right: 35px; color: white; font-size: 28px; cursor: pointer; background: rgba(0,0,0,0.3); width: 45px; height: 45px; display: flex; align-items: center; justify-content: center; border-radius: 50%; transition: 0.2s;}
        .close-btn:hover { background: #ef4444; transform: rotate(90deg);}

        @media (max-width: 1000px) { 
            .media-action-grid { grid-template-columns: 1fr; }
            .maps-grid { grid-template-columns: 1fr; } 
            .nav-links.desktop-only { display: none; }
        }
    </style>
</head>
<body>

    <div id="lightbox" class="lightbox">
        <div class="close-btn" onclick="closeLightbox()">&times;</div>
        <div class="lb-controls">
            <button class="lb-btn" onclick="changeSlide(-1)"><i class="fa-solid fa-chevron-left"></i></button>
            <button class="lb-btn" onclick="changeSlide(1)"><i class="fa-solid fa-chevron-right"></i></button>
        </div>
        <div style="overflow: hidden; display: flex; justify-content: center; align-items: center; width: 100%; height: 85vh;">
            <img id="lightbox-img" src="" style="transition: transform 0.2s ease;">
        </div>
        <div style="display: flex; gap: 15px; margin-top: 15px; align-items: center;">
            <button class="lb-btn" onclick="zoomImage(-0.2)" style="width: 40px; height: 40px; font-size: 16px;" title="Zoom Out"><i class="fa-solid fa-magnifying-glass-minus"></i></button>
            <div style="color: white; font-weight: 600; font-size: 14px; background: rgba(0,0,0,0.5); padding: 5px 15px; border-radius: 20px;">
                <span id="lb-counter">1</span> / <?= count($js_images) ?>
            </div>
            <button class="lb-btn" onclick="zoomImage(0.2)" style="width: 40px; height: 40px; font-size: 16px;" title="Zoom In"><i class="fa-solid fa-magnifying-glass-plus"></i></button>
        </div>
    </div>

    <nav class="nav">
        <div class="nav-left">
            <a href="index.php" class="brand-wrapper">
                <img src="assets/logo.png" alt="JEJ Logo" style="height: 45px; width: auto; margin-right: 12px; border-radius: 8px;">
                <span class="nav-brand">JEJ Surveying</span>
            </a>
        </div>
        <div class="nav-links desktop-only">
            <a href="index.php">Properties</a>
            <?php if(isset($_SESSION['user_id'])): ?>
                <?php if(in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])): ?>
                    <a href="admin.php"><i class="fa-solid fa-gauge" style="margin-right: 5px;"></i> Admin Panel</a>
                <?php else: ?>
                    <a href="my_reservations.php"><i class="fa-solid fa-file-signature" style="margin-right: 5px;"></i> My Reservations</a>
                <?php endif; ?>
            <?php endif; ?>
        </div>
        <div class="user-menu">
            <span style="background: var(--gray-light); padding: 6px 12px; border-radius: 8px; border: 1px solid var(--gray-border);"><i class="fa-solid fa-user" style="color: var(--primary); margin-right: 5px;"></i> <?= htmlspecialchars($_SESSION['fullname']) ?></span>
            <a href="logout.php" style="color: #ef4444; margin-left:15px; font-size: 16px; transition: 0.2s;" onmouseover="this.style.color='#b91c1c'" onmouseout="this.style.color='#ef4444'" title="Logout"><i class="fa-solid fa-right-from-bracket"></i></a>
        </div>
    </nav>

    <main class="main-content">

        <div class="breadcrumb">
            <a href="index.php"><i class="fa-solid fa-house" style="margin-right: 4px;"></i> Home</a>
            <i class="fa-solid fa-chevron-right" style="font-size: 10px;"></i>
            <span><?= htmlspecialchars($lot['location']) ?></span>
            <i class="fa-solid fa-chevron-right" style="font-size: 10px;"></i>
            <strong style="color: #1e293b;">Block <?= htmlspecialchars($lot['block_no']) ?> Lot <?= htmlspecialchars($lot['lot_no']) ?></strong>
        </div>

        <div class="media-action-grid">
            
            <div class="gallery-section">
                <div class="main-img-box" onclick="openLightbox('<?= $main_img ?>')">
                    <img src="<?= $main_img ?>" class="main-img">
                    <span class="badge <?= $lot['status'] ?>" style="top:20px; left:20px; right:auto;"><?= $lot['status'] ?></span>
                    <div style="position: absolute; bottom: 20px; right: 20px; background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(4px); color: white; padding: 8px 16px; border-radius: 8px; font-size: 12px; font-weight: 600; pointer-events: none; border: 1px solid rgba(255,255,255,0.2);">
                        <i class="fa-solid fa-expand" style="margin-right: 5px;"></i> View Full Screen
                    </div>
                </div>

                <div class="gallery-grid">
                    <div class="thumb-box" onclick="openLightbox('<?= $main_img ?>')">
                        <img src="<?= $main_img ?>" class="thumb-img">
                    </div>
                    <?= $gallery_html ?>
                </div>

                <div class="specs-card">
                    <span class="prop-type"><?= $lot['property_type'] ?: 'Residential Lot' ?></span>
                    
                    <h2>Block <?= htmlspecialchars($lot['block_no']) ?>, Lot <?= htmlspecialchars($lot['lot_no']) ?></h2>
                    
                    <div class="location">
                        <i class="fa-solid fa-location-dot" style="color: #ef4444;"></i> <?= htmlspecialchars($lot['location']) ?>
                    </div>

                    <div class="price-grid">
                        <div>
                            <small>Lot Area</small>
                            <strong><?= number_format($lot['area']) ?> m²</strong>
                        </div>
                        <div>
                            <small>Price / SQM</small>
                            <strong>₱<?= number_format($lot['price_per_sqm']) ?></strong>
                        </div>
                        <div class="total-row">
                            <small>Total Contract Price</small>
                            <strong>₱<?= number_format($lot['total_price']) ?></strong>
                        </div>
                    </div>

                    <h4>Property Overview</h4>
                    <p><?= nl2br(htmlspecialchars($lot['property_overview'] ?? 'No additional description available for this property.')) ?></p>
                </div>
            </div>

            <div class="form-section">
                <div class="form-card">
                    <?php if($lot['status'] == 'AVAILABLE'): ?>
                        <div class="form-header">
                            <h3 style="font-size: 22px; font-weight: 800; margin: 0 0 5px; color: #0f172a;">Reserve Property</h3>
                            <p style="color: #64748b; font-size: 13px; margin: 0;">Fill out the details below to secure this lot.</p>
                        </div>

                        <div class="form-body">
                            <form action="actions.php" method="POST" enctype="multipart/form-data">
                                <input type="hidden" name="action" value="reserve">
                                <input type="hidden" name="lot_id" value="<?= $lot['id'] ?>">
                                
                                <div class="form-group">
                                    <label>Full Name</label>
                                    <input type="text" name="fullname" class="form-control" value="<?= htmlspecialchars($_SESSION['fullname']) ?>" required>
                                </div>
                                
                                <div class="form-group">
                                    <label>Email Address <span style="color:#ef4444">*</span></label>
                                    <input type="email" name="email" class="form-control" required placeholder="E.g., juandelacruz@gmail.com">
                                </div>

                                <div style="display:flex; gap:12px;">
                                    <div class="form-group" style="flex:1;">
                                        <label>Mobile No. <span style="color:#ef4444">*</span></label>
                                        <input type="text" name="contact_number" class="form-control" placeholder="09XX XXX XXXX" required>
                                    </div>
                                    <div class="form-group" style="flex:1;">
                                        <label>Birth Date <span style="color:#ef4444">*</span></label>
                                        <input type="date" name="birth_date" class="form-control" required>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label>Complete Home Address <span style="color:#ef4444">*</span></label>
                                    <input type="text" name="address" class="form-control" placeholder="House No, Street, Brgy, City" required>
                                </div>
                                
                                <div style="border-top: 1px dashed #cbd5e1; margin: 25px 0;"></div>
                                
                                <div style="margin-bottom: 15px;">
                                    <strong style="font-size: 14px; color: #1e293b;">Required Documents</strong>
                                    <p style="font-size: 12px; color: #64748b; margin: 4px 0 0;">Please upload clear photos (JPG, PNG).</p>
                                </div>

                                <div class="form-group">
                                    <label>1. Valid Government ID</label>
                                    <input type="file" name="valid_id" class="form-control" style="padding: 9px 12px; background: white;" accept="image/*" required>
                                </div>
                                <div class="form-group">
                                    <label>2. Selfie holding the ID</label>
                                    <input type="file" name="selfie_id" class="form-control" style="padding: 9px 12px; background: white;" accept="image/*" required>
                                </div>
                                <div class="form-group">
                                    <label>3. Proof of Reservation Payment</label>
                                    <input type="file" name="proof" class="form-control" style="padding: 9px 12px; background: white;" accept="image/*" required>
                                    <small style="display:block; margin-top:6px; color:#3b82f6; font-size:11px; font-weight:600;"><i class="fa-solid fa-circle-info"></i> Standard reservation fee is usually ₱10,000.</small>
                                </div>

                                <button type="submit" class="btn-submit"><i class="fa-solid fa-paper-plane" style="margin-right: 6px;"></i> Submit Reservation Request</button>
                            </form>
                        </div>
                    <?php else: ?>
                        <div style="text-align:center; padding: 60px 30px; background: #fff5f5; height: 100%; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 400px;">
                            <div style="width: 70px; height: 70px; background: #fee2e2; color: #dc2626; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 30px; margin-bottom: 20px;">
                                <i class="fa-solid fa-lock"></i>
                            </div>
                            <h3 style="margin: 0 0 10px; color: #991b1b; font-size: 22px; font-weight: 800;">Property Unavailable</h3>
                            <p style="color: #b91c1c; font-size: 14px; line-height: 1.5; margin: 0;">This lot has already been marked as <strong><?= htmlspecialchars($lot['status']) ?></strong> and cannot be reserved online at this time.</p>
                            <a href="index.php" style="margin-top: 25px; padding: 12px 24px; background: white; color: #dc2626; border: 1px solid #fecdd3; border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 13px; transition: 0.2s;">Browse Other Lots</a>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div class="maps-grid">
            
            <div class="map-wrapper" id="schemeWrapper">
                <div class="map-header">
                    <span><i class="fa-solid fa-map" style="color: var(--primary); margin-right: 5px;"></i> Subdivision Plan</span>
                    <div style="display: flex; gap: 8px;">
                        <span style="width:14px; height:14px; border-radius:4px; background:rgba(34, 197, 94, 0.8); border: 1px solid #15803d;" title="Available"></span>
                        <span style="width:14px; height:14px; border-radius:4px; background:rgba(234, 179, 8, 0.8); border: 1px solid #a16207;" title="Reserved"></span>
                        <span style="width:14px; height:14px; border-radius:4px; background:rgba(239, 68, 68, 0.9); border: 1px solid #991b1b;" title="Sold"></span>
                    </div>
                </div>
                
                <div class="svg-container" id="svgContainer">
                    <div class="map-controls-overlay">
                        <button class="zoom-btn" onclick="toggleMapFullscreen()" title="Toggle Fullscreen"><i class="fa-solid fa-expand" id="fsIcon"></i></button>
                        <button class="zoom-btn" onclick="zoomMap(0.2)" title="Zoom In"><i class="fa-solid fa-plus"></i></button>
                        <button class="zoom-btn" onclick="zoomMap(-0.2)" title="Zoom Out"><i class="fa-solid fa-minus"></i></button>
                        <button class="zoom-btn" onclick="resetMap()" title="Reset View"><i class="fa-solid fa-rotate-left"></i></button>
                    </div>
                    
                    <svg id="schemeMap" viewBox="0 0 1464 1052" preserveAspectRatio="xMidYMid meet">
                        <image href="<?= $current_map ?>?v=<?= time() ?>" x="0" y="0" width="1464" height="1052"></image>
                        <?php foreach ($all_lots as $l): 
                            $points = htmlspecialchars($l['coordinates'] ?? '');
                            if(empty($points)) continue;
                            
                            $isCurrent = ($l['id'] == $lot['id']);
                            $statusClass = strtolower($l['status']);
                            $polyClass = "lot " . $statusClass . ($isCurrent ? " lot-focused" : " lot-dimmed");
                        ?>
                        <polygon class="<?= $polyClass ?>" points="<?= $points ?>">
                            <title>Block <?= htmlspecialchars($l['block_no']) ?> - Lot <?= htmlspecialchars($l['lot_no']) ?></title>
                        </polygon>
                        <?php endforeach; ?>
                    </svg>
                </div>
                
                <div style="padding: 12px 20px; background: white; font-size: 12px; color: #64748b; border-top: 1px solid var(--gray-border); flex-shrink: 0; text-align: center; display: flex; align-items: center; justify-content: center; gap: 10px;">
                    <span style="color: #00e5ff; text-shadow: 0 0 2px rgba(0,229,255,0.8); font-weight: 800;"><i class="fa-solid fa-location-crosshairs"></i> Current Lot Highlighted in Cyan</span>
                    <span style="color: #cbd5e1;">|</span>
                    <span style="font-weight: 600;">Map Status Key: <strong style="color:#dc2626;">Sold (Red)</strong>, <strong style="color:#d97706;">Reserved (Yellow)</strong>, <strong style="color:#059669;">Available (Green)</strong></span>
                </div>
            </div>

            <?php if(!empty($lot['latitude'])): ?>
            <div class="map-wrapper geo-wrapper">
                <div class="map-header">
                    <span><i class="fa-solid fa-earth-asia" style="color: var(--primary); margin-right: 5px;"></i> Geographic Location</span>
                </div>
                <div id="map-display"></div>
            </div>
            <?php else: ?>
            <div class="map-wrapper geo-wrapper" style="justify-content: center; align-items: center; background: #f8fafc; border: 1px dashed #cbd5e1;">
                <i class="fa-solid fa-location-dot" style="font-size: 30px; color: #cbd5e1; margin-bottom: 10px;"></i>
                <span style="color: #94a3b8; font-size: 13px; font-weight: 500;">No exact geographic pin available.</span>
            </div>
            <?php endif; ?>

        </div>
    </main>

    <footer style="background: white; border-top: 1px solid var(--gray-border); padding: 40px 5%; margin-top: 50px; text-align: center;">
        <div style="margin-bottom: 20px;">
            <img src="assets/logo.png" alt="JEJ Logo" style="height: 60px; width: auto; border-radius: 8px;">
        </div>
        <p style="margin: 0; font-size: 16px; font-weight: 800; color: #1e293b;">JEJ Surveying Services</p>
        <p style="color: #64748b; font-size: 14px; margin: 5px 0 0;">Professional surveying and subdivision blueprint solutions.</p>
        <div style="margin-top: 30px; font-size: 13px; color: #94a3b8; font-weight: 500;">
            &copy; <?= date('Y') ?> All Rights Reserved.
        </div>
    </footer>

    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        // --- LEAFLET MAP LOGIC ---
        <?php if(!empty($lot['latitude'])): ?>
        var map = L.map('map-display').setView([<?= $lot['latitude'] ?>, <?= $lot['longitude'] ?>], 16);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors'
        }).addTo(map);
        
        var markerIcon = L.divIcon({
            className: 'custom-div-icon',
            html: "<div style='background-color:#ef4444; width:16px; height:16px; border-radius:50%; border:3px solid white; box-shadow:0 0 10px rgba(0,0,0,0.5);'></div>",
            iconSize: [22, 22],
            iconAnchor: [11, 11]
        });
        L.marker([<?= $lot['latitude'] ?>, <?= $lot['longitude'] ?>], {icon: markerIcon}).addTo(map)
         .bindPopup("<b>Block <?= $lot['block_no'] ?> Lot <?= $lot['lot_no'] ?></b><br>JEJ Surveying");
        
        setTimeout(() => { map.invalidateSize(); }, 500);
        <?php endif; ?>

        // --- SCHEME MAP LOGIC (ZOOM & PAN & FULLSCREEN) ---
        let mapScale = 1;
        let mapPanX = 0;
        let mapPanY = 0;
        let isPanning = false;
        let startDrag = { x: 0, y: 0 };

        const svgContainer = document.getElementById('svgContainer');
        const schemeMap = document.getElementById('schemeMap');
        const schemeWrapper = document.getElementById('schemeWrapper');
        const fsIcon = document.getElementById('fsIcon');

        window.addEventListener('load', function() {
            const focusedLot = document.querySelector('.lot-focused');
            if (svgContainer && focusedLot) {
                const bbox = focusedLot.getBBox();
                const scaleX = svgContainer.clientWidth / 1464; 
                const scrollTargetX = (bbox.x * scaleX) - (svgContainer.clientWidth / 2);
                if(scrollTargetX > 0) { svgContainer.scrollLeft = scrollTargetX; }
            }
        });

        function setMapTransform() {
            schemeMap.style.transform = `translate(${mapPanX}px, ${mapPanY}px) scale(${mapScale})`;
        }

        function zoomMap(delta) {
            mapScale += delta;
            if(mapScale < 0.5) mapScale = 0.5;
            if(mapScale > 5) mapScale = 5;
            setMapTransform();
        }

        function resetMap() {
            mapScale = 1; mapPanX = 0; mapPanY = 0;
            setMapTransform();
        }

        function toggleMapFullscreen() {
            schemeWrapper.classList.toggle('fullscreen');
            if (schemeWrapper.classList.contains('fullscreen')) {
                fsIcon.classList.remove('fa-expand');
                fsIcon.classList.add('fa-compress');
                document.body.style.overflow = 'hidden';
            } else {
                fsIcon.classList.remove('fa-compress');
                fsIcon.classList.add('fa-expand');
                document.body.style.overflow = 'auto';
            }
            resetMap();
        }

        svgContainer.addEventListener('wheel', function(e) {
            e.preventDefault();
            const delta = e.deltaY > 0 ? -0.1 : 0.1;
            zoomMap(delta);
        });

        svgContainer.addEventListener('mousedown', function(e) {
            e.preventDefault();
            isPanning = true;
            startDrag = { x: e.clientX - mapPanX, y: e.clientY - mapPanY };
            svgContainer.style.cursor = 'grabbing';
        });

        window.addEventListener('mouseup', function() {
            isPanning = false;
            svgContainer.style.cursor = 'grab';
        });

        window.addEventListener('mousemove', function(e) {
            if (!isPanning) return;
            e.preventDefault();
            mapPanX = (e.clientX - startDrag.x);
            mapPanY = (e.clientY - startDrag.y);
            setMapTransform();
        });


        // --- LIGHTBOX LOGIC ---
        const allImages = <?php echo json_encode($js_images); ?>;
        let currentIdx = 0;
        let currentLbZoom = 1;

        function zoomImage(step) {
            currentLbZoom += step;
            if (currentLbZoom < 0.5) currentLbZoom = 0.5; 
            if (currentLbZoom > 4) currentLbZoom = 4;     
            document.getElementById('lightbox-img').style.transform = `scale(${currentLbZoom})`;
        }

        function resetLbZoom() {
            currentLbZoom = 1;
            document.getElementById('lightbox-img').style.transform = `scale(${currentLbZoom})`;
        }

        function openLightbox(src) {
            const index = allImages.indexOf(src);
            if(index !== -1) {
                currentIdx = index;
                resetLbZoom();
                updateLightboxImage();
                document.getElementById('lightbox').style.display = 'flex';
                document.body.style.overflow = 'hidden'; 
            }
        }

        function closeLightbox() {
            document.getElementById('lightbox').style.display = 'none';
            document.body.style.overflow = 'auto'; 
            resetLbZoom();
        }

        function changeSlide(step) {
            currentIdx += step;
            if (currentIdx >= allImages.length) currentIdx = 0;
            if (currentIdx < 0) currentIdx = allImages.length - 1;
            resetLbZoom();
            updateLightboxImage();
        }

        function updateLightboxImage() {
            document.getElementById('lightbox-img').src = allImages[currentIdx];
            document.getElementById('lb-counter').innerText = currentIdx + 1;
        }

        document.addEventListener('keydown', function(e) {
            if(document.getElementById('lightbox').style.display === 'flex') {
                if(e.key === 'ArrowLeft') changeSlide(-1);
                if(e.key === 'ArrowRight') changeSlide(1);
                if(e.key === 'Escape') closeLightbox();
            }
            if(e.key === 'Escape' && schemeWrapper.classList.contains('fullscreen')) {
                toggleMapFullscreen();
            }
        });
    </script>
</body>
</html>