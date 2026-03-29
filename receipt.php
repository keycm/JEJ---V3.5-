<?php
// receipt.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    die("Access Denied");
}

if(!isset($_GET['id'])){
    die("Invalid Request");
}

$id = $_GET['id'];

// Fetch Reservation Data
$stmt = $conn->prepare("SELECT r.*, u.fullname, l.block_no, l.lot_no, l.area, l.price_per_sqm, l.total_price, l.location, l.property_type 
                        FROM reservations r 
                        JOIN users u ON r.user_id = u.id 
                        JOIN lots l ON r.lot_id = l.id 
                        WHERE r.id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$data = $stmt->get_result()->fetch_assoc();

if(!$data) die("Reservation not found.");

// Determine Payment Term String
$payment_term_display = (strtoupper($data['payment_type']) === 'CASH') ? 'Full Payment (Spot Cash)' : 'Downpayment (Installment)';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Official Receipt #<?= str_pad($data['id'], 6, '0', STR_PAD_LEFT) ?> - EcoEstates</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        /* Professional Business Receipt CSS */
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f4f6f8;
            color: #333;
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }

        .receipt-container {
            background: #ffffff;
            width: 100%;
            max-width: 850px;
            padding: 50px 60px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.08);
            border-top: 8px solid #2e7d32; /* Corporate Green */
            position: relative;
            box-sizing: border-box;
        }

        /* Header Section */
        .header-section {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #edf2f7;
            padding-bottom: 25px;
            margin-bottom: 35px;
        }

        .company-info h1 {
            margin: 0 0 5px 0;
            font-size: 26px;
            font-weight: 800;
            color: #1b5e20;
            letter-spacing: -0.5px;
        }

        .company-info p {
            margin: 3px 0;
            font-size: 13px;
            color: #555;
            line-height: 1.5;
        }

        .receipt-title {
            text-align: right;
        }

        .receipt-title h2 {
            margin: 0 0 5px 0;
            font-size: 28px;
            font-weight: 800;
            color: #2d3748;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .receipt-title p {
            margin: 0;
            font-size: 14px;
            color: #718096;
            font-weight: 500;
        }

        /* Two Column Info Section */
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 40px;
            margin-bottom: 40px;
        }

        .info-box {
            background: #fafafa;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #edf2f7;
        }

        .info-box h3 {
            margin: 0 0 15px 0;
            font-size: 13px;
            text-transform: uppercase;
            color: #2e7d32;
            font-weight: 700;
            letter-spacing: 0.5px;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 8px;
        }

        .info-row {
            display: flex;
            margin-bottom: 8px;
            font-size: 13px;
            line-height: 1.5;
        }

        .info-row span.label {
            width: 110px;
            color: #718096;
            font-weight: 500;
        }

        .info-row span.value {
            flex: 1;
            color: #2d3748;
            font-weight: 600;
        }

        /* Table Section */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }

        th {
            background-color: #f7fafc;
            color: #4a5568;
            text-align: left;
            padding: 14px 16px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid #e2e8f0;
            border-top: 1px solid #e2e8f0;
        }

        td {
            padding: 16px;
            font-size: 14px;
            color: #2d3748;
            border-bottom: 1px solid #edf2f7;
            vertical-align: top;
        }

        .text-right { text-align: right; }
        .text-center { text-align: center; }

        .item-title {
            font-weight: 700;
            color: #1a202c;
            margin-bottom: 4px;
            display: block;
        }

        .item-desc {
            font-size: 12px;
            color: #718096;
        }

        /* Totals Section */
        .totals-container {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 50px;
        }

        .totals-box {
            width: 350px;
            background: #f8fafc;
            border: 1px solid #edf2f7;
            border-radius: 8px;
            padding: 20px;
        }

        .total-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            font-size: 14px;
            color: #4a5568;
        }

        .total-row.grand-total {
            border-top: 2px solid #e2e8f0;
            margin-top: 10px;
            padding-top: 15px;
            font-size: 18px;
            font-weight: 800;
            color: #2e7d32;
        }

        /* Signatures */
        .signatures {
            display: flex;
            justify-content: space-between;
            margin-top: 60px;
            padding-top: 20px;
        }

        .sig-box {
            width: 40%;
            text-align: center;
        }

        .sig-line {
            border-top: 1px solid #a0aec0;
            margin-bottom: 8px;
            padding-top: 8px;
            font-weight: 700;
            color: #2d3748;
            font-size: 15px;
        }

        .sig-title {
            font-size: 12px;
            color: #718096;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Footer */
        .footer {
            margin-top: 50px;
            text-align: center;
            font-size: 11px;
            color: #a0aec0;
            border-top: 1px solid #edf2f7;
            padding-top: 20px;
        }

        /* Print Button */
        .btn-print {
            position: fixed;
            bottom: 40px;
            right: 40px;
            background: #2e7d32;
            color: white;
            padding: 16px 32px;
            border: none;
            border-radius: 50px;
            cursor: pointer;
            font-weight: 700;
            font-size: 15px;
            box-shadow: 0 10px 20px rgba(46, 125, 50, 0.2);
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .btn-print:hover {
            background: #1b5e20;
            transform: translateY(-2px);
            box-shadow: 0 12px 25px rgba(27, 94, 32, 0.3);
        }

        /* Print Styles */
        @media print {
            body { 
                background: white; 
                padding: 0; 
                display: block; 
            }
            .receipt-container { 
                box-shadow: none; 
                border-top: none; 
                width: 100%; 
                max-width: 100%; 
                padding: 20px; 
            }
            .btn-print { 
                display: none; 
            }
        }
    </style>
</head>
<body>

    <button class="btn-print" onclick="window.print()">
        <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
            <polyline points="6 9 6 2 18 2 18 9"></polyline>
            <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path>
            <rect x="6" y="14" width="12" height="8"></rect>
        </svg>
        Print Receipt
    </button>

    <div class="receipt-container">
        
        <div class="header-section">
            <div class="company-info">
                <h1>JEJ Surveying / EcoEstates</h1>
                <p>123 Green Valley Road, Eco City, Philippines</p>
                <p>Tel: (045) 123-4567 | Mobile: +63 917 123 4567</p>
                <p>Email: billing@ecoestates.com | Web: www.ecoestates.com</p>
            </div>
            <div class="receipt-title">
                <h2>Official Receipt</h2>
                <p>Receipt Number: <strong>#<?= str_pad($data['id'], 6, '0', STR_PAD_LEFT) ?></strong></p>
                <p>Date Issued: <strong><?= date('F d, Y', strtotime($data['reservation_date'])) ?></strong></p>
            </div>
        </div>

        <div class="info-grid">
            <div class="info-box">
                <h3>Billed To / Buyer Details</h3>
                <div class="info-row"><span class="label">Client Name:</span> <span class="value"><?= htmlspecialchars($data['fullname']) ?></span></div>
                <div class="info-row"><span class="label">Contact No:</span> <span class="value"><?= htmlspecialchars($data['contact_number']) ?></span></div>
                <div class="info-row"><span class="label">Email Address:</span> <span class="value"><?= htmlspecialchars($data['email']) ?></span></div>
                <div class="info-row"><span class="label">Home Address:</span> <span class="value"><?= htmlspecialchars($data['buyer_address']) ?></span></div>
            </div>

            <div class="info-box">
                <h3>Transaction Status</h3>
                <div class="info-row"><span class="label">Reference ID:</span> <span class="value">RES-<?= date('Y') ?>-<?= str_pad($data['id'], 5, '0', STR_PAD_LEFT) ?></span></div>
                
                <div class="info-row">
                    <span class="label">Payment Terms:</span> 
                    <span class="value" style="color: #0ea5e9; font-weight: 700;"><?= $payment_term_display ?></span>
                </div>

                <div class="info-row"><span class="label">Status:</span> 
                    <span class="value" style="color: <?= $data['status'] == 'APPROVED' ? '#2e7d32' : ($data['status'] == 'PENDING' ? '#d97706' : '#dc2626') ?>; font-weight: 800;">
                        <?= strtoupper(htmlspecialchars($data['status'])) ?>
                    </span>
                </div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th width="45%">Property Description</th>
                    <th class="text-center" width="15%">Lot Area</th>
                    <th class="text-right" width="20%">Price per Sqm</th>
                    <th class="text-right" width="20%">Total Amount</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>
                        <span class="item-title">Block <?= htmlspecialchars($data['block_no']) ?>, Lot <?= htmlspecialchars($data['lot_no']) ?></span>
                        <span class="item-desc">
                            <?= htmlspecialchars($data['property_type']) ?><br>
                            Location: <?= htmlspecialchars($data['location']) ?>
                        </span>
                    </td>
                    <td class="text-center" style="vertical-align: middle;">
                        <?= number_format($data['area'], 2) ?> m²
                    </td>
                    <td class="text-right" style="vertical-align: middle;">
                        ₱<?= number_format($data['price_per_sqm'], 2) ?>
                    </td>
                    <td class="text-right" style="vertical-align: middle; font-weight: 600; color: #1a202c;">
                        ₱<?= number_format($data['total_price'], 2) ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <div class="totals-container">
            <div class="totals-box">
                <div class="total-row">
                    <span>Subtotal</span>
                    <span>₱<?= number_format($data['total_price'], 2) ?></span>
                </div>
                <div class="total-row">
                    <span>VAT (Inclusive)</span>
                    <span>₱0.00</span>
                </div>
                <div class="total-row grand-total">
                    <span>Total Contract Price</span>
                    <span>₱<?= number_format($data['total_price'], 2) ?></span>
                </div>
            </div>
        </div>

        <div class="signatures">
            <div class="sig-box">
                <div class="sig-line"><?= htmlspecialchars($data['fullname']) ?></div>
                <div class="sig-title">Buyer's Printed Name & Signature</div>
            </div>
            <div class="sig-box">
                <div class="sig-line">System Administrator</div>
                <div class="sig-title">Authorized Representative</div>
            </div>
        </div>

        <div class="footer">
            <p>This is a system-generated official receipt for reservation purposes. <br>
            Any alterations to this document will render it invalid.<br>
            <strong>JEJ Surveying & EcoEstates Land Inc.</strong> | All Rights Reserved &copy; <?= date('Y') ?></p>
        </div>

    </div>

</body>
</html>