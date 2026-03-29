<?php
// config.php

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Database Connection Settings
$host = 'localhost';
$user = 'root';
$pass = ''; // Leave blank if using default XAMPP
$dbname = 'eco_land'; // Change if your database name is different

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Database Connection failed: " . $conn->connect_error);
}

// ==========================================
// SYSTEM HELPER FUNCTIONS
// ==========================================

// 1. Audit Trail Logger
if (!function_exists('logActivity')) {
    function logActivity($conn, $user_id, $action, $details = "") {
        $stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)");
        if($stmt){
            $stmt->bind_param("iss", $user_id, $action, $details);
            $stmt->execute();
            $stmt->close();
        }
    }
}

// 2. Auto-Generate OR Number (Official Receipts)
if (!function_exists('generateORNumber')) {
    function generateORNumber($conn) {
        $prefix = "OR-" . date("Ymd") . "-";
        $query = "SELECT or_number FROM transactions WHERE or_number LIKE '$prefix%' ORDER BY id DESC LIMIT 1";
        $result = $conn->query($query);
        if($result && $result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $last_num = (int)str_replace($prefix, "", $row['or_number']);
            $new_num = str_pad($last_num + 1, 4, "0", STR_PAD_LEFT);
        } else {
            $new_num = "0001";
        }
        return $prefix . $new_num;
    }
}

// 3. Auto-Generate CV Number (Check Vouchers)
if (!function_exists('generateCVNumber')) {
    function generateCVNumber($conn) {
        $prefix = "CV-" . date("Ymd") . "-";
        $query = "SELECT or_number FROM transactions WHERE or_number LIKE '$prefix%' ORDER BY id DESC LIMIT 1";
        $result = $conn->query($query);
        if($result && $result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $last_num = (int)str_replace($prefix, "", $row['or_number']);
            $new_num = str_pad($last_num + 1, 4, "0", STR_PAD_LEFT);
        } else {
            $new_num = "0001";
        }
        return $prefix . $new_num;
    }
}

// 4. Archive & Delete History Logger
if (!function_exists('logDeletion')) {
    function logDeletion($conn, $module, $record_id, $data_array, $user_id) {
        // Convert the array of old data into a JSON string
        $data_json = json_encode($data_array); 
        
        $stmt = $conn->prepare("INSERT INTO delete_history (module_name, record_id, record_data, deleted_by) VALUES (?, ?, ?, ?)");
        if($stmt){
            $stmt->bind_param("sisi", $module, $record_id, $data_json, $user_id);
            $stmt->execute();
            $stmt->close();
        }
    }
}

// 5. Security Checker: Require Admin/Manager
if (!function_exists('checkAdmin')) {
    function checkAdmin() {
        if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
            header("Location: login.php");
            exit();
        }
    }
}

// 6. Security Checker: Require basic Login
if (!function_exists('checkLogin')) {
    function checkLogin() {
        if(!isset($_SESSION['user_id'])){
            header("Location: login.php");
            exit();
        }
    }
}
?>