<?php
// my_reservations.php
include 'config.php';

// Only allow logged in users who are NOT admins
if(!isset($_SESSION['user_id'])){
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];

$alert_msg = '';
$alert_type = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pay_dp'])) {
    $res_id = isset($_POST['res_id']) ? (int)$_POST['res_id'] : 0;
    $dp_input_raw = trim($_POST['dp_amount'] ?? '');
    $dp_input_clean = str_replace([',', ' '], '', $dp_input_raw);
    $dp_input = is_numeric($dp_input_clean) ? (float)$dp_input_clean : 0;
    $payment_method = strtoupper(trim($_POST['payment_method'] ?? ''));
    $payment_ref = trim($_POST['payment_reference'] ?? '');
    $allowed_methods = ['CASH', 'GCASH', 'INSTAPAY', 'BANK TRANSFER'];

    if ($res_id > 0) {
        $checkStmt = $conn->prepare("SELECT r.id, r.status, l.block_no, l.lot_no, l.total_price FROM reservations r JOIN lots l ON l.id = r.lot_id WHERE r.id = ? AND r.user_id = ? LIMIT 1");
        $checkStmt->bind_param("ii", $res_id, $user_id);
        $checkStmt->execute();
        $reservation = $checkStmt->get_result()->fetch_assoc();
        $checkStmt->close();

        if ($reservation && $reservation['status'] === 'APPROVED') {
            $dp_amount = round((float)$reservation['total_price'] * 0.20, 2);

            if (!in_array($payment_method, $allowed_methods, true)) {
                $alert_msg = "Please select a valid payment option.";
                $alert_type = "error";
            } elseif ($payment_method !== 'CASH' && $payment_ref === '') {
                $alert_msg = "Reference number is required for GCash, InstaPay, or Bank Transfer.";
                $alert_type = "error";
            } elseif ($dp_input <= 0) {
                $alert_msg = "Please enter a valid down payment amount.";
                $alert_type = "error";
            } elseif (abs($dp_input - $dp_amount) > 0.009) {
                $alert_msg = "Entered amount does not match required 20% down payment of PHP " . number_format($dp_amount, 2) . ".";
                $alert_type = "error";
            } else {

                $existsStmt = $conn->prepare("SELECT id FROM transactions WHERE type='INCOME' AND description LIKE ? AND ABS(amount - ?) < 1 LIMIT 1");
                $descLike = "%Down Payment%Res#" . $res_id . "%";
                $existsStmt->bind_param("sd", $descLike, $dp_amount);
                $existsStmt->execute();
                $alreadyPaid = $existsStmt->get_result()->num_rows > 0;
                $existsStmt->close();

                if ($alreadyPaid) {
                    $alert_msg = "Down payment already recorded for this reservation.";
                    $alert_type = "info";
                } else {
                    $catQuery = $conn->query("SELECT id FROM accounting_categories WHERE name='Lot Sales' LIMIT 1");
                    if ($catQuery && $catQuery->num_rows > 0) {
                        $cat_id = (int)$catQuery->fetch_assoc()['id'];
                    } else {
                        $conn->query("INSERT INTO accounting_categories (name, group_name, type) VALUES ('Lot Sales', 'Income', 'INCOME')");
                        $cat_id = (int)$conn->insert_id;
                    }

                    $projQuery = $conn->query("SELECT id FROM projects LIMIT 1");
                    if ($projQuery && $projQuery->num_rows > 0) {
                        $proj_id = (int)$projQuery->fetch_assoc()['id'];
                    } else {
                        $conn->query("INSERT INTO projects (name) VALUES ('General Operations')");
                        $proj_id = (int)$conn->insert_id;
                    }

                    $or_number = generateORNumber($conn);
                    $tx_date = date('Y-m-d');
                    $tx_type = 'INCOME';
                    $method_note = "Method: {$payment_method}";
                    $clean_ref = preg_replace('/[^A-Za-z0-9\-_ ]/', '', $payment_ref);
                    $ref_note = $clean_ref !== '' ? " | Ref: {$clean_ref}" : '';
                    $description = "Down Payment for Lot (Block {$reservation['block_no']} Lot {$reservation['lot_no']}) - Res#{$res_id} | {$method_note}{$ref_note}";

                    $txStmt = $conn->prepare("INSERT INTO transactions (or_number, transaction_date, type, category_id, project_id, amount, description, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                    $txStmt->bind_param("sssiidsi", $or_number, $tx_date, $tx_type, $cat_id, $proj_id, $dp_input, $description, $user_id);

                    if ($txStmt->execute()) {
                        $alert_msg = "Down payment submitted successfully.";
                        $alert_type = "success";
                    } else {
                        $alert_msg = "Failed to process down payment.";
                        $alert_type = "error";
                    }
                    $txStmt->close();
                }
            }
        } else {
            $alert_msg = "Invalid reservation or reservation is not approved.";
            $alert_type = "error";
        }
    } else {
        $alert_msg = "Invalid reservation ID.";
        $alert_type = "error";
    }
}

$query = "SELECT r.*, l.block_no, l.lot_no, l.property_type, l.total_price, l.lot_image, p.name as phase_name 
          FROM reservations r 
          JOIN lots l ON r.lot_id = l.id 
          LEFT JOIN phases p ON l.phase_id = p.id 
          WHERE r.user_id = ? 
          ORDER BY r.reservation_date DESC";

$stmt = $conn->prepare($query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Reservations | JEJ Surveying Services</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@500;700;800;900&family=Open+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <link rel="stylesheet" href="assets/modern.css">
</head>
<body style="background-color: #F7FAFC;">

    <nav class="nav">
        <div class="brand-wrapper">
            <a href="index.php" style="display: flex; align-items: center; gap: 10px;">
                <img src="assets/logo.png" alt="JEJ Logo" style="height: 45px; width: auto; border-radius: 6px;">
                <span class="nav-brand">JEJ Surveying Services</span>
            </a>
        </div>
        
        <div class="nav-links desktop-only">
            <a href="index.php">Properties</a>
            <a href="my_reservations.php" class="active">My Reservations</a>
        </div>

        <div class="user-menu">
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
        </div>
    </nav>

    <div class="container" style="margin-top: 100px; min-height: 60vh;">
        <h2 class="section-title"><i class="fa-solid fa-book-bookmark" style="color: var(--primary); margin-right: 10px;"></i> My Reservations</h2>

        <?php if($alert_msg): ?>
            <div style="padding: 14px 16px; border-radius: 10px; margin-bottom: 18px; font-weight: 700; font-size: 13px; background: <?= $alert_type==='success' ? '#F0FFF4' : ($alert_type==='info' ? '#EBF8FF' : '#FFF5F5') ?>; color: <?= $alert_type==='success' ? '#2F855A' : ($alert_type==='info' ? '#2B6CB0' : '#C53030') ?>; border: 1px solid <?= $alert_type==='success' ? '#C6F6D5' : ($alert_type==='info' ? '#BEE3F8' : '#FED7D7') ?>;">
                <?= htmlspecialchars($alert_msg) ?>
            </div>
        <?php endif; ?>

        <?php if($result->num_rows > 0): ?>
            <div class="table-container" style="background: white; padding: 20px; border-radius: 12px; box-shadow: var(--shadow-soft);">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="text-align: left; background: #EDF2F7; color: #4A5568; font-size: 13px; text-transform: uppercase;">
                            <th style="padding: 15px;">Property</th>
                            <th style="padding: 15px;">Date Reserved</th>
                            <th style="padding: 15px;">Total Price</th>
                            <th style="padding: 15px;">Status</th>
                            <th style="padding: 15px;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while($row = $result->fetch_assoc()): ?>
                        <tr style="border-bottom: 1px solid #E2E8F0;">
                            <td style="padding: 15px;">
                                <div style="display: flex; align-items: center; gap: 15px;">
                                    <img src="<?= $row['lot_image'] ? 'uploads/'.$row['lot_image'] : 'assets/default_lot.jpg' ?>" style="width: 50px; height: 50px; border-radius: 8px; object-fit: cover;">
                                    <div>
                                        <strong>Block <?= $row['block_no'] ?>, Lot <?= $row['lot_no'] ?></strong>
                                        <div style="font-size: 12px; color: #718096;"><?= $row['phase_name'] ?> - <?= $row['property_type'] ?></div>
                                    </div>
                                </div>
                            </td>
                            <td style="padding: 15px; font-size: 14px; color: #4A5568;">
                                <?= date('F d, Y h:i A', strtotime($row['reservation_date'])) ?>
                            </td>
                            <td style="padding: 15px; font-weight: 600; font-family: 'Open Sans', sans-serif;">
                                ₱<?= number_format($row['total_price']) ?>
                            </td>
                            <td style="padding: 15px;">
                                <?php 
                                    $badges = [
                                        'PENDING'  => ['bg'=>'#FEFCBF', 'col'=>'#975A16'],
                                        'APPROVED' => ['bg'=>'#C6F6D5', 'col'=>'#22543D'],
                                        'CANCELLED'=> ['bg'=>'#FED7D7', 'col'=>'#822727']
                                    ];
                                    $b = $badges[$row['status']] ?? $badges['PENDING'];
                                ?>
                                <span style="background: <?= $b['bg'] ?>; color: <?= $b['col'] ?>; padding: 5px 12px; border-radius: 6px; font-size: 11px; font-weight: 800; display: inline-block;">
                                    <?= $row['status'] ?>
                                </span>
                            </td>
                            <td style="padding: 15px;">
                                <?php
                                    $dp_paid = false;
                                    $dp_paid_date = '';
                                    $dp_tx_id = 0;
                                    if ($row['status'] === 'APPROVED') {
                                        $row_dp = round((float)$row['total_price'] * 0.20, 2);
                                        $checkPayStmt = $conn->prepare("SELECT id, transaction_date FROM transactions WHERE type='INCOME' AND description LIKE ? AND ABS(amount - ?) < 1 LIMIT 1");
                                        $checkDesc = "%Down Payment%Res#" . (int)$row['id'] . "%";
                                        $checkPayStmt->bind_param("sd", $checkDesc, $row_dp);
                                        $checkPayStmt->execute();
                                        $paidRes = $checkPayStmt->get_result()->fetch_assoc();
                                        $checkPayStmt->close();
                                        if ($paidRes) {
                                            $dp_paid = true;
                                            $dp_tx_id = (int)$paidRes['id'];
                                            $dp_paid_date = date('M d, Y', strtotime($paidRes['transaction_date']));
                                        }
                                    }
                                ?>

                                <?php if($row['status'] !== 'APPROVED'): ?>
                                    <span style="font-size: 12px; color: #A0AEC0; font-weight: 700;">Waiting for approval</span>
                                <?php elseif($dp_paid): ?>
                                    <span style="background: #C6F6D5; color: #22543D; padding: 6px 10px; border-radius: 8px; font-size: 11px; font-weight: 800; display: inline-block;">DP Paid</span>
                                    <div style="font-size: 11px; color: #718096; margin-top: 5px;">Paid on <?= $dp_paid_date ?></div>
                                    <a href="buyer_receipt.php?tx_id=<?= $dp_tx_id ?>" target="_blank" style="margin-top:6px; display:inline-block; background:#2B6CB0; color:#fff; border-radius:8px; padding:7px 10px; font-size:11px; font-weight:800; text-decoration:none;">
                                        <i class="fa-solid fa-receipt"></i> Receipt
                                    </a>
                                <?php else: ?>
                                    <?php $required_dp = round((float)$row['total_price'] * 0.20, 2); ?>
                                    <button type="button" onclick="openDpModal(<?= (int)$row['id'] ?>, <?= json_encode($required_dp) ?>, '<?= htmlspecialchars($row['block_no'], ENT_QUOTES) ?>', '<?= htmlspecialchars($row['lot_no'], ENT_QUOTES) ?>')" style="background: #2F855A; color: white; border: none; padding: 8px 12px; border-radius: 8px; font-size: 12px; font-weight: 800; cursor: pointer;">
                                        <i class="fa-solid fa-credit-card"></i> Pay Down Payment
                                    </button>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <div style="text-align: center; padding: 60px; color: #A0AEC0; background: #fff; border-radius: 16px; box-shadow: var(--shadow-soft); border: 1px solid #EDF2F7;">
                <i class="fa-solid fa-folder-open" style="font-size: 40px; margin-bottom: 20px; color: #CBD5E0;"></i>
                <h3 style="color:#4A5568; margin-bottom: 5px;">No reservations found</h3>
                <p style="font-size: 14px;">You haven't made any lot reservations yet.</p>
                <a href="index.php" style="color: white; background: var(--primary); padding: 10px 20px; border-radius: 8px; font-weight: 700; margin-top: 15px; display: inline-block; text-decoration: none; font-size: 14px;">Browse Properties</a>
            </div>
        <?php endif; ?>
    </div>

    <div id="dpModal" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,0.45); z-index:9999; align-items:center; justify-content:center; padding:14px;">
        <div style="background:#fff; width:100%; max-width:460px; border-radius:14px; box-shadow:0 10px 35px rgba(0,0,0,0.2); overflow:hidden;">
            <div style="padding:16px 18px; border-bottom:1px solid #E2E8F0; display:flex; justify-content:space-between; align-items:center;">
                <strong style="font-size:18px; color:#1A202C;">Pay Down Payment</strong>
                <button type="button" onclick="closeDpModal()" style="border:none; background:none; font-size:22px; color:#A0AEC0; cursor:pointer;">&times;</button>
            </div>
            <form method="POST" onsubmit="return confirmDpAmount();" style="padding:18px;">
                <input type="hidden" name="res_id" id="dpResId" value="">
                <input type="hidden" id="dpRequiredRaw" value="">

                <div style="font-size:13px; color:#4A5568; margin-bottom:8px;" id="dpPropertyText">Property:</div>
                <div style="margin-bottom:14px; padding:10px; border:1px solid #E2E8F0; border-radius:10px; background:#F7FAFC;">
                    <div style="font-size:11px; color:#718096; text-transform:uppercase; font-weight:700;">Required Down Payment (20%)</div>
                    <div id="dpRequiredText" style="font-size:22px; font-weight:800; color:#22543D; margin-top:4px;">PHP 0.00</div>
                </div>

                <label for="dpAmountInput" style="font-size:12px; font-weight:700; color:#4A5568; display:block; margin-bottom:6px;">Enter Amount to Pay</label>
                <input type="text" name="dp_amount" id="dpAmountInput" required placeholder="e.g. 1200000.00" style="width:100%; border:1px solid #CBD5E0; border-radius:8px; padding:10px 12px; font-size:14px; margin-bottom:14px;">

                <label for="dpMethodInput" style="font-size:12px; font-weight:700; color:#4A5568; display:block; margin-bottom:6px;">Payment Option</label>
                <select name="payment_method" id="dpMethodInput" required onchange="showPaymentInfo(this.value)" style="width:100%; border:1px solid #CBD5E0; border-radius:8px; padding:10px 12px; font-size:14px; margin-bottom:10px; background:#fff;">
                    <option value="">Select payment option</option>
                    <option value="CASH">Cash</option>
                    <option value="GCASH">GCash</option>
                    <option value="INSTAPAY">InstaPay</option>
                    <option value="BANK TRANSFER">Bank Transfer</option>
                </select>

                <!-- Payment account info box -->
                <div id="dpPaymentInfo" style="display:none; margin-bottom:14px; background:#EBF8FF; border:1px solid #BEE3F8; border-radius:10px; padding:12px 14px;"></div>

                <label for="dpRefInput" style="font-size:12px; font-weight:700; color:#4A5568; display:block; margin-bottom:6px;">Reference No. (required for online payment)</label>
                <input type="text" name="payment_reference" id="dpRefInput" placeholder="e.g. 1234567890" style="width:100%; border:1px solid #CBD5E0; border-radius:8px; padding:10px 12px; font-size:14px; margin-bottom:14px;">

                <button type="submit" name="pay_dp" style="width:100%; background:#2F855A; color:#fff; border:none; border-radius:9px; padding:11px; font-weight:800; font-size:13px; cursor:pointer;">
                    Confirm Down Payment
                </button>
            </form>
        </div>
    </div>

    <footer class="footer">
        <div style="margin-bottom: 25px;">
            <img src="assets/logo.png" alt="JEJ Logo" style="height: 60px; width: auto; border-radius: 8px; background: white; padding: 5px;">
        </div>
        <p><strong>JEJ Surveying Services</strong></p>
        <p style="opacity:0.6; margin-top:10px; font-size: 14px;">Professional surveying and blueprint solutions.</p>
        <div style="margin-top: 40px; font-size: 12px; opacity: 0.4;">
            &copy; <?= date('Y') ?> All Rights Reserved.
        </div>
    </footer>

    <script>
    function formatPeso(num) {
        return 'PHP ' + Number(num).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }

    // ── Payment account details ──────────────────────────────────────────────
    // Update account details below. Online methods now use API checkout.
    var PAYMENT_ACCOUNTS = {
        'CASH': {
            color: '#744210', bg: '#FFFFF0', border: '#F6E05E',
            icon: '💵', title: 'Cash Payment',
            api_method: '',
            rows: [
                { label: 'Note', value: 'Please pay at our office.' },
                { label: 'Address', value: 'JEJ Surveying Services Office' }
            ]
        },
        'GCASH': {
            color: '#0D3D8C', bg: '#EFF6FF', border: '#3B82F6',
            icon: '📱', title: 'GCash',
            api_method: 'GCASH',
            button_label: 'Open in GCash',
            rows: [
                { label: 'Account Name', value: 'MA*K RO**O I** T.' },
                { label: 'GCash Number', value: '0936 551 ....' },
                { label: 'User ID', value: '..........WE92L9' }
            ]
        },
        'INSTAPAY': {
            color: '#065F46', bg: '#ECFDF5', border: '#6EE7B7',
            icon: '⚡', title: 'InstaPay',
            api_method: 'INSTAPAY',
            button_label: 'Proceed to InstaPay',
            rows: [
                { label: 'Account Name', value: 'JEJ Surveying Services' },
                { label: 'Account Number', value: '1234-5678-9012' },
                { label: 'Bank', value: 'BDO Unibank' }
            ]
        },
        'BANK TRANSFER': {
            color: '#1E3A5F', bg: '#EFF6FF', border: '#93C5FD',
            icon: '🏦', title: 'Bank Transfer',
            api_method: 'BANK TRANSFER',
            button_label: 'Proceed to Bank Transfer',
            rows: [
                { label: 'Bank', value: 'BDO Unibank' },
                { label: 'Account Name', value: 'JEJ Surveying Services' },
                { label: 'Account Number', value: '1234567890' },
                { label: 'Branch', value: 'Main Branch' }
            ]
        }
    };

    function showPaymentInfo(method) {
        var box = document.getElementById('dpPaymentInfo');
        if (!method || !PAYMENT_ACCOUNTS[method]) {
            box.style.display = 'none';
            return;
        }
        var info = PAYMENT_ACCOUNTS[method];

        // Account rows
        var rowsHtml = '';
        info.rows.forEach(function(r) {
            rowsHtml += '<div style="display:flex; justify-content:space-between; font-size:12px; padding:4px 0; border-bottom:1px dashed ' + info.border + ';">'
                      + '<span style="color:#718096;">' + r.label + '</span>'
                      + '<span style="font-weight:700; color:' + info.color + ';">' + r.value + '</span>'
                      + '</div>';
        });

        // API checkout button for online payment methods
        var payActionHtml = '';
        if (info.api_method) {
            payActionHtml = '<div style="margin-top:12px;">'
                          + '<button type="button" onclick="startApiCheckout(\'' + method + '\')" '
                          + 'style="width:100%; border:0; background:' + info.color + '; color:#fff; border-radius:8px; padding:10px 12px; font-size:12px; font-weight:800; cursor:pointer;">'
                          + (info.button_label ? info.button_label : ('Proceed to ' + info.title + ' Payment'))
                          + '</button>'
                          + '</div>';
        }

        var html = '<div style="font-size:13px; font-weight:800; color:' + info.color + '; margin-bottom:8px;">' + info.icon + ' ' + info.title + '</div>'
                 + rowsHtml
                 + payActionHtml
                 + '<div style="font-size:11px; color:#718096; margin-top:8px; padding-top:6px; border-top:1px solid ' + info.border + ';">For online methods, tap the button to open secure checkout, then enter your payment reference below.</div>';

        box.style.background = info.bg;
        box.style.borderColor = info.border;
        box.innerHTML = html;
        box.style.display = 'block';
    }

    function startApiCheckout(method) {
        var resId = parseInt(document.getElementById('dpResId').value || '0', 10);
        var amount = parseFloat(document.getElementById('dpRequiredRaw').value || '0');

        if (!resId || !amount || !method) {
            alert('Unable to start payment checkout. Missing reservation details.');
            return;
        }

        fetch('create_checkout_session.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                reservation_id: resId,
                payment_method: method,
                amount: amount
            })
        })
        .then(function(res) { return res.json(); })
        .then(function(data) {
            if (!data || !data.success || !data.checkout_url) {
                var msg = data && data.message ? data.message : 'Unable to create payment checkout session.';
                alert(msg);
                return;
            }
            window.open(data.checkout_url, '_blank');
        })
        .catch(function() {
            alert('Checkout connection failed. Please try again.');
        });
    }
    // ────────────────────────────────────────────────────────────────────────

    function openDpModal(resId, requiredDp, blockNo, lotNo) {
        document.getElementById('dpResId').value = resId;
        document.getElementById('dpRequiredRaw').value = requiredDp;
        document.getElementById('dpRequiredText').textContent = formatPeso(requiredDp);
        document.getElementById('dpPropertyText').textContent = 'Property: Block ' + blockNo + ', Lot ' + lotNo;
        document.getElementById('dpAmountInput').value = Number(requiredDp).toFixed(2);
        document.getElementById('dpMethodInput').value = '';
        document.getElementById('dpRefInput').value = '';
        showPaymentInfo('');
        document.getElementById('dpModal').style.display = 'flex';
    }

    function closeDpModal() {
        document.getElementById('dpModal').style.display = 'none';
    }

    function confirmDpAmount() {
        var required = parseFloat(document.getElementById('dpRequiredRaw').value || '0');
        var input = document.getElementById('dpAmountInput').value.replace(/,/g, '').trim();
        var entered = parseFloat(input || '0');
        var method = document.getElementById('dpMethodInput').value;

        if (!entered || entered <= 0) {
            alert('Please enter a valid amount.');
            return false;
        }

        if (Math.abs(entered - required) > 0.009) {
            alert('Entered amount must match required down payment: ' + formatPeso(required));
            return false;
        }

        if (!method) {
            alert('Please select a payment option.');
            return false;
        }

        if (method !== 'CASH') {
            var ref = document.getElementById('dpRefInput').value.trim();
            if (!ref) {
                alert('Reference number is required for GCash, InstaPay, or Bank Transfer.');
                return false;
            }
        }

        return true;
    }

    window.addEventListener('click', function(e) {
        var modal = document.getElementById('dpModal');
        if (e.target === modal) {
            closeDpModal();
        }
    });
    </script>

</body>
</html>
