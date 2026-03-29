<?php
// statement_of_account.php
include 'config.php';

// Failsafe admin check if function exists, otherwise rely on session
if(function_exists('checkAdmin')){
    checkAdmin();
} elseif(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    echo '<div style="color:#e11d48; font-weight:700; text-align:center; padding:20px;">Access Denied.</div>';
    exit;
}

$res_id = isset($_GET['res_id']) ? (int)$_GET['res_id'] : 0;
if ($res_id <= 0) {
    echo '<div style="color:#e11d48; font-weight:700; text-align:center; padding:20px;">Invalid reservation ID.</div>';
    exit;
}

// Fetch Reservation Details
$stmt = $conn->prepare(
    "SELECT r.id, r.reservation_date, r.payment_type, r.installment_months, r.monthly_payment,
            u.fullname,
            l.block_no, l.lot_no, l.total_price
     FROM reservations r
     JOIN users u ON u.id = r.user_id
     JOIN lots l ON l.id = r.lot_id
     WHERE r.id = ?"
);
$stmt->bind_param('i', $res_id);
$stmt->execute();
$res_data = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$res_data) {
    echo '<div style="color:#e11d48; font-weight:700; text-align:center; padding:20px;">Reservation not found.</div>';
    exit;
}

$total_price = (float)$res_data['total_price'];
$down_payment = $total_price * 0.20;
$balance = $total_price - $down_payment;
$months = (int)($res_data['installment_months'] ?? 0);
$monthly_payment = (float)($res_data['monthly_payment'] ?? 0);
$buyer_name = htmlspecialchars($res_data['fullname']);

// --- FETCH TRANSACTIONS (Using Failsafe for reservation_id) ---
$has_res_id_col = false;
$colCheck = $conn->query("SHOW COLUMNS FROM transactions LIKE 'reservation_id'");
if($colCheck && $colCheck->num_rows > 0) {
    $has_res_id_col = true;
}

if ($has_res_id_col) {
    $tx_stmt = $conn->prepare("SELECT id, transaction_date, amount, description FROM transactions WHERE type = 'INCOME' AND reservation_id = ? ORDER BY transaction_date ASC, id ASC");
    $tx_stmt->bind_param('i', $res_id);
} else {
    $tx_stmt = $conn->prepare("SELECT id, transaction_date, amount, description FROM transactions WHERE type = 'INCOME' AND description LIKE ? ORDER BY transaction_date ASC, id ASC");
    $tx_like = "%Res#" . $res_id . "%";
    $tx_stmt->bind_param('s', $tx_like);
}

$tx_stmt->execute();
$tx_result = $tx_stmt->get_result();
$transactions = [];
while ($row = $tx_result->fetch_assoc()) {
    $transactions[] = $row;
}
$tx_stmt->close();

// --- PROCESS DOWN PAYMENT VS AMORTIZATION ---
$dp_paid_amount = 0;
$dp_paid_dates = [];
$remaining_tx = []; // Transactions allocated for monthly amortization

foreach ($transactions as $tx) {
    $desc = strtolower($tx['description']);
    // If explicitly marked as Amortization, save for later
    if (strpos($desc, 'amortization') !== false) {
        $remaining_tx[] = $tx;
    } else {
        // Otherwise, it counts towards the Down Payment
        $dp_paid_amount += (float)$tx['amount'];
        $dp_paid_dates[] = date('M d, Y', strtotime($tx['transaction_date']));
    }
}

// Calculate DP Status
$is_dp_fully_paid = ($dp_paid_amount >= ($down_payment - 0.50)); // -0.50 tolerance for rounding
$dp_remaining = max(0, $down_payment - $dp_paid_amount);
$last_dp_date = !empty($dp_paid_dates) ? end($dp_paid_dates) : '';

$reservation_ts = strtotime($res_data['reservation_date']);
$first_due_ts = strtotime('+20 days', $reservation_ts);

function formatPeso($value) {
    return '₱ ' . number_format((float)$value, 2);
}

// --- RENDER SUMMARY HEADER ---
echo '<div style="display:grid; grid-template-columns: 1fr 1fr; gap:15px; margin-bottom:25px; background: #f8fafc; padding: 20px; border-radius: 12px; border: 1px solid #e2e8f0;">';
    echo '<div>';
        echo '<div style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 700; margin-bottom: 4px;">Buyer Information</div>';
        echo '<div style="font-size: 16px; font-weight: 800; color: #1e293b; margin-bottom: 10px;">' . $buyer_name . '</div>';
        echo '<div style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 700; margin-bottom: 4px;">Property Details</div>';
        echo '<div style="font-size: 14px; font-weight: 700; color: #2e7d32;">Block ' . htmlspecialchars($res_data['block_no']) . ' Lot ' . htmlspecialchars($res_data['lot_no']) . '</div>';
    echo '</div>';
    
    echo '<div>';
        echo '<div style="display: flex; justify-content: space-between; margin-bottom: 8px; border-bottom: 1px dashed #cbd5e1; padding-bottom: 8px;">';
            echo '<strong style="color: #475569;">Total Contract Price:</strong>';
            echo '<span style="font-weight: 800; color: #1e293b;">' . formatPeso($total_price) . '</span>';
        echo '</div>';
        
        echo '<div style="display: flex; justify-content: space-between; margin-bottom: 8px;">';
            echo '<strong style="color: #475569;">Target Down Payment (20%):</strong>';
            echo '<span style="font-weight: 700; color: #334155;">' . formatPeso($down_payment) . '</span>';
        echo '</div>';

        // Dynamic DP Status Render
        echo '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; background: white; padding: 8px 12px; border-radius: 6px; border: 1px solid #e2e8f0;">';
            echo '<strong style="color: #475569;">DP Status:</strong>';
            if ($is_dp_fully_paid) {
                echo '<span style="background:#d1fae5; color:#059669; padding:4px 10px; border-radius:6px; font-weight:800; font-size:11px;">FULLY PAID (' . $last_dp_date . ')</span>';
            } elseif ($dp_paid_amount > 0) {
                echo '<div style="text-align: right;">';
                    echo '<span style="background:#dbeafe; color:#2563eb; padding:4px 10px; border-radius:6px; font-weight:800; font-size:11px;">PARTIALLY PAID</span>';
                    echo '<div style="font-size: 11px; color: #64748b; margin-top: 4px;">Paid: <b style="color:#059669;">'.formatPeso($dp_paid_amount).'</b> | Bal: <b style="color:#e11d48;">'.formatPeso($dp_remaining).'</b></div>';
                echo '</div>';
            } else {
                echo '<span style="background:#ffe4e6; color:#e11d48; padding:4px 10px; border-radius:6px; font-weight:800; font-size:11px;">UNPAID</span>';
            }
        echo '</div>';

        echo '<div style="display: flex; justify-content: space-between; border-top: 2px solid #e2e8f0; padding-top: 8px; margin-top: 8px;">';
            echo '<strong style="color: #1e293b;">TCP Balance (Amortization):</strong>';
            echo '<span style="font-weight: 800; color: #1e293b;">' . formatPeso($balance) . '</span>';
        echo '</div>';

    echo '</div>';
echo '</div>';

// --- RENDER AMORTIZATION SCHEDULE ---
if ($res_data['payment_type'] !== 'INSTALLMENT' || $months <= 0 || $monthly_payment <= 0) {
    echo '<div style="padding:20px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:12px; color:#475569; text-align:center;">';
    echo '<i class="fa-solid fa-circle-info" style="font-size: 24px; color: #94a3b8; display: block; margin-bottom: 10px;"></i>';
    echo '<strong>No installment schedule configured.</strong><br><span style="font-size: 13px;">This reservation is either spot cash or terms have not been set yet.</span>';
    echo '</div>';
    exit;
}

$used_ids = [];
echo '<h3 style="font-size: 16px; font-weight: 800; color: #1e293b; margin-bottom: 15px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;"><i class="fa-solid fa-calendar-check" style="color:#2e7d32; margin-right:8px;"></i> Amortization Schedule</h3>';
echo '<div style="overflow:auto; border-radius: 12px; border: 1px solid #e2e8f0;">';
echo '<table style="width:100%; border-collapse:collapse; font-size:13px; font-family: \'Inter\', sans-serif;">';
echo '<thead><tr style="background:#f8fafc;">';
echo '<th style="text-align:left; padding:12px 16px; border-bottom:1px solid #e2e8f0; color:#64748b; font-weight:700;">Month #</th>';
echo '<th style="text-align:left; padding:12px 16px; border-bottom:1px solid #e2e8f0; color:#64748b; font-weight:700;">Due Date</th>';
echo '<th style="text-align:left; padding:12px 16px; border-bottom:1px solid #e2e8f0; color:#64748b; font-weight:700;">Amount Due</th>';
echo '<th style="text-align:center; padding:12px 16px; border-bottom:1px solid #e2e8f0; color:#64748b; font-weight:700;">Status</th>';
echo '<th style="text-align:right; padding:12px 16px; border-bottom:1px solid #e2e8f0; color:#64748b; font-weight:700;">Date Paid</th>';
echo '</tr></thead><tbody>';

for ($i = 1; $i <= $months; $i++) {
    $due_ts = strtotime('+' . $i . ' month', $first_due_ts);
    $due = date('M d, Y', $due_ts);

    $paid = false;
    $paid_date = '-';

    foreach ($remaining_tx as $tx) {
        if (in_array($tx['id'], $used_ids, true)) {
            continue;
        }

        // Match installment payments by near-equal amount (tolerance of 2 pesos for rounding)
        if (abs((float)$tx['amount'] - $monthly_payment) < 2) {
            $paid = true;
            $paid_date = date('M d, Y', strtotime($tx['transaction_date']));
            $used_ids[] = $tx['id'];
            break;
        }
    }

    $status_html = $paid
        ? '<span style="background:#d1fae5; color:#059669; padding:4px 10px; border-radius:6px; font-weight:800; font-size:10px; letter-spacing: 0.5px;">PAID</span>'
        : '<span style="background:#ffe4e6; color:#e11d48; padding:4px 10px; border-radius:6px; font-weight:800; font-size:10px; letter-spacing: 0.5px;">UNPAID</span>';

    $row_bg = $paid ? '#ffffff' : '#fef2f2'; // Slight red tint for unpaid rows

    echo '<tr style="background: '.$row_bg.';">';
    echo '<td style="padding:12px 16px; border-bottom:1px solid #e2e8f0; font-weight:600; color:#475569;">Month ' . $i . '</td>';
    echo '<td style="padding:12px 16px; border-bottom:1px solid #e2e8f0; font-weight:600; color:#1e293b;">' . $due . '</td>';
    echo '<td style="padding:12px 16px; border-bottom:1px solid #e2e8f0; font-weight:700; color:#334155;">' . formatPeso($monthly_payment) . '</td>';
    echo '<td style="padding:12px 16px; border-bottom:1px solid #e2e8f0; text-align:center;">' . $status_html . '</td>';
    echo '<td style="padding:12px 16px; border-bottom:1px solid #e2e8f0; text-align:right; color:#64748b; font-size: 12px;">' . $paid_date . '</td>';
    echo '</tr>';
}

echo '</tbody></table>';
echo '</div>';
?>