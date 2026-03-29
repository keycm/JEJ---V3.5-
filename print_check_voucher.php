<?php
// print_check_voucher.php
include 'config.php';

// Security Check
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    die("Access Denied");
}

if(!isset($_GET['cv']) || empty($_GET['cv'])){
    die("Invalid Request. Check Voucher Number is missing.");
}

$cv_number = $_GET['cv'];

// Query the actual 'transactions' table using the 'or_number'
$stmt = $conn->prepare("SELECT * FROM transactions WHERE or_number = ? AND is_check = 1");
$stmt->bind_param("s", $cv_number);
$stmt->execute();
$data = $stmt->get_result()->fetch_assoc();

if(!$data) {
    die("Check Voucher not found in the database.");
}

// Custom function to convert number to words (No PHP extensions required)
function numberToWords($num) {
    $ones = array(
        0 => "Zero", 1 => "One", 2 => "Two", 3 => "Three", 4 => "Four", 5 => "Five", 6 => "Six", 7 => "Seven", 8 => "Eight", 9 => "Nine",
        10 => "Ten", 11 => "Eleven", 12 => "Twelve", 13 => "Thirteen", 14 => "Fourteen", 15 => "Fifteen", 16 => "Sixteen", 17 => "Seventeen", 18 => "Eighteen", 19 => "Nineteen"
    );
    $tens = array(
        0 => "Zero", 1 => "Ten", 2 => "Twenty", 3 => "Thirty", 4 => "Forty", 5 => "Fifty", 6 => "Sixty", 7 => "Seventy", 8 => "Eighty", 9 => "Ninety"
    );
    $hundreds = array("Hundred", "Thousand", "Million", "Billion", "Trillion");

    $num = number_format((float)$num, 2, ".", "");
    $num_arr = explode(".", $num);
    $wholenum = $num_arr[0];
    $decnum = $num_arr[1];
    
    if($wholenum == 0) {
        $rettxt = "Zero";
    } else {
        $whole_arr = array_reverse(explode(",", number_format($wholenum)));
        ksort($whole_arr);
        
        $rettxt = "";
        foreach($whole_arr as $key => $i){
            if($i < 20){
                $rettxt = ($i > 0 ? $ones[intval($i)] . " " : "") . ($key > 0 && $i > 0 ? $hundreds[$key] . " " : "") . $rettxt;
            } elseif($i < 100){
                $rettxt = $tens[substr($i, 0, 1)] . " " . ($ones[substr($i, 1, 1)] != "Zero" ? $ones[substr($i, 1, 1)] . " " : "") . ($key > 0 ? $hundreds[$key] . " " : "") . $rettxt;
            } else {
                $rettxt = $ones[substr($i, 0, 1)] . " " . $hundreds[0] . " " . 
                          ($tens[substr($i, 1, 1)] != "Zero" ? $tens[substr($i, 1, 1)] . " " : "") . 
                          ($ones[substr($i, 2, 1)] != "Zero" ? $ones[substr($i, 2, 1)] . " " : "") . 
                          ($key > 0 ? $hundreds[$key] . " " : "") . $rettxt;
            }
        }
    }
    
    $rettxt = trim($rettxt) . " Pesos";
    
    // Handle Cents
    if($decnum > 0){
        $rettxt .= " and " . $decnum . "/100";
    }
    
    return $rettxt . " Only";
}

$amount = isset($data['amount']) ? (float)$data['amount'] : 0.00;
$amount_words = numberToWords($amount);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Voucher <?= htmlspecialchars($data['or_number']) ?> - EcoEstates</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        /* Professional Check Voucher CSS */
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f4f6f8;
            color: #1a202c;
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }

        .voucher-container {
            background: #ffffff;
            width: 100%;
            max-width: 900px;
            padding: 50px 60px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.08);
            border-top: 8px solid #2e7d32; /* Corporate Green */
            position: relative;
            box-sizing: border-box;
        }

        /* Header */
        .header {
            text-align: center;
            border-bottom: 2px solid #2e7d32;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 800;
            color: #1b5e20;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .header p {
            margin: 5px 0 0 0;
            font-size: 14px;
            color: #4a5568;
        }

        .voucher-title {
            text-align: center;
            font-size: 22px;
            font-weight: 800;
            color: #2d3748;
            margin: 20px 0;
            text-transform: uppercase;
            letter-spacing: 2px;
            background-color: #f8fafc;
            padding: 10px;
            border: 1px solid #e2e8f0;
        }

        /* Top Details Grid */
        .top-details {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }

        .detail-row {
            display: flex;
            margin-bottom: 12px;
            font-size: 14px;
        }

        .detail-row .label {
            width: 120px;
            font-weight: 700;
            color: #4a5568;
            text-transform: uppercase;
            font-size: 12px;
            align-self: flex-end;
        }

        .detail-row .value {
            flex: 1;
            border-bottom: 1px solid #cbd5e1;
            padding-bottom: 2px;
            font-weight: 600;
            color: #1a202c;
        }

        /* Amount Box */
        .amount-box {
            border: 2px solid #2e7d32;
            padding: 15px;
            text-align: center;
            border-radius: 8px;
            background: #f0fdf4;
        }

        .amount-box .currency {
            font-size: 18px;
            font-weight: 700;
            color: #1b5e20;
        }

        .amount-box .total-number {
            font-size: 28px;
            font-weight: 800;
            color: #1b5e20;
        }

        /* Particulars Table */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            border: 1px solid #cbd5e1;
        }

        th {
            background-color: #f1f5f9;
            color: #334155;
            text-align: left;
            padding: 12px 15px;
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            border-bottom: 2px solid #cbd5e1;
            border-right: 1px solid #cbd5e1;
        }

        th:last-child { border-right: none; }

        td {
            padding: 15px;
            font-size: 14px;
            color: #1a202c;
            border-bottom: 1px solid #e2e8f0;
            border-right: 1px solid #e2e8f0;
            vertical-align: top;
        }

        td:last-child { border-right: none; }

        .text-right { text-align: right; }
        .text-center { text-align: center; }
        
        /* Amount in words */
        .amount-words-container {
            background: #f8fafc;
            padding: 15px 20px;
            border-left: 4px solid #2e7d32;
            margin-bottom: 40px;
            font-size: 14px;
        }

        .amount-words-container span.label {
            font-weight: 700;
            color: #4a5568;
            text-transform: uppercase;
            font-size: 12px;
            margin-right: 10px;
        }

        .amount-words-container span.value {
            font-weight: 700;
            color: #1a202c;
            font-size: 15px;
            text-transform: uppercase;
        }

        /* Signatories */
        .signatories {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-top: 50px;
        }

        .sig-box {
            text-align: center;
        }

        .sig-line {
            border-top: 1px solid #64748b;
            margin-top: 40px;
            padding-top: 8px;
            font-weight: 700;
            color: #1a202c;
            font-size: 14px;
            min-height: 20px;
        }

        .sig-title {
            font-size: 11px;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
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
            z-index: 1000;
        }

        .btn-print:hover {
            background: #1b5e20;
            transform: translateY(-2px);
            box-shadow: 0 12px 25px rgba(27, 94, 32, 0.3);
        }

        /* Print CSS */
        @media print {
            body { 
                background: white; 
                padding: 0; 
                display: block; 
            }
            .voucher-container { 
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
        Print Voucher
    </button>

    <div class="voucher-container">
        
        <div class="header">
            <h1>JEJ Surveying / EcoEstates Land Inc.</h1>
            <p>123 Green Valley Road, Eco City, Philippines | Tel: (045) 123-4567</p>
        </div>

        <div class="voucher-title">
            Check Voucher
        </div>

        <div class="top-details">
            <div class="left-col">
                <div class="detail-row">
                    <span class="label">Payee:</span>
                    <span class="value"><?= htmlspecialchars($data['payee'] ?? 'N/A') ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Bank Name:</span>
                    <span class="value"><?= htmlspecialchars($data['bank_name'] ?? 'N/A') ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Check No:</span>
                    <span class="value" style="font-family: monospace; font-size: 16px;"><?= htmlspecialchars($data['check_number'] ?? 'N/A') ?></span>
                </div>
            </div>
            
            <div class="right-col">
                <div class="detail-row">
                    <span class="label" style="width: 60px;">Date:</span>
                    <span class="value text-right"><?= date('F d, Y', strtotime($data['transaction_date'])) ?></span>
                </div>
                <div class="detail-row">
                    <span class="label" style="width: 60px;">CV No:</span>
                    <span class="value text-right" style="color: #dc2626; font-weight: 800;">
                        <?= htmlspecialchars($data['or_number']) ?>
                    </span>
                </div>
                
                <div class="amount-box" style="margin-top: 15px;">
                    <span class="currency">₱</span>
                    <span class="total-number"><?= number_format($amount, 2) ?></span>
                </div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th width="75%">Particulars / Description</th>
                    <th class="text-right" width="25%">Amount</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td style="height: 120px;"> <strong>Payment Disbursement</strong><br>
                        <span style="color: #4a5568; font-size: 13px;">
                            <?= nl2br(htmlspecialchars($data['description'] ?? 'No additional description provided.')) ?>
                        </span>
                    </td>
                    <td class="text-right" style="font-weight: 600;">
                        ₱<?= number_format($amount, 2) ?>
                    </td>
                </tr>
                <tr>
                    <td class="text-right" style="font-weight: 700; text-transform: uppercase; font-size: 12px; background: #f8fafc;">Total Amount</td>
                    <td class="text-right" style="font-weight: 800; font-size: 16px; color: #1b5e20; background: #f8fafc;">
                        ₱<?= number_format($amount, 2) ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <div class="amount-words-container">
            <span class="label">The sum of:</span>
            <span class="value"><?= htmlspecialchars($amount_words) ?></span>
        </div>

        <div class="signatories">
            <div class="sig-box">
                <div class="sig-line"><?= htmlspecialchars($_SESSION['fullname'] ?? 'Admin') ?></div>
                <div class="sig-title">Prepared By</div>
            </div>
            <div class="sig-box">
                <div class="sig-line"></div>
                <div class="sig-title">Checked By</div>
            </div>
            <div class="sig-box">
                <div class="sig-line"></div>
                <div class="sig-title">Approved By</div>
            </div>
            <div class="sig-box">
                <div class="sig-line"></div>
                <div class="sig-title">Received By / Date</div>
            </div>
        </div>

    </div>

</body>
</html>