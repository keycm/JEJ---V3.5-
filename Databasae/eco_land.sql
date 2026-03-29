-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 29, 2026 at 11:19 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `eco_land`
--

-- --------------------------------------------------------

--
-- Table structure for table `accounting_categories`
--

CREATE TABLE `accounting_categories` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `group_name` varchar(50) NOT NULL,
  `type` enum('INCOME','EXPENSE') NOT NULL DEFAULT 'EXPENSE'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `accounting_categories`
--

INSERT INTO `accounting_categories` (`id`, `name`, `group_name`, `type`) VALUES
(1, 'Electric Bill', 'Bills', 'EXPENSE'),
(2, 'Internet Bill', 'Bills', 'EXPENSE'),
(3, 'Water Bill', 'Bills', 'EXPENSE'),
(4, 'Payment for Subdivide', 'Voucher', 'EXPENSE'),
(5, 'Payment for Titling', 'Voucher', 'EXPENSE'),
(6, 'Food', 'Others', 'EXPENSE'),
(7, 'Miscellaneous', 'Others', 'EXPENSE'),
(8, 'Lot Sales', 'Income', 'INCOME'),
(9, 'Lot Reservation', '', 'INCOME'),
(10, 'Monthly Amortization', '', 'INCOME'),
(11, 'Office Supplies', '', 'EXPENSE'),
(12, 'Agent Commission', '', 'EXPENSE'),
(13, 'Site Development', '', 'EXPENSE'),
(14, 'Miscellaneous', '', 'EXPENSE');

-- --------------------------------------------------------

--
-- Table structure for table `audit_logs`
--

CREATE TABLE `audit_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `action` varchar(255) NOT NULL,
  `details` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `audit_logs`
--

INSERT INTO `audit_logs` (`id`, `user_id`, `action`, `details`, `created_at`) VALUES
(1, 1, 'Exported Transactions to Excel', '', '2026-03-23 08:26:05'),
(2, 1, 'Exported Transactions to Excel', '', '2026-03-23 08:45:03'),
(3, 1, 'Exported Transactions to Excel', '', '2026-03-23 09:01:29'),
(4, 1, 'Approved Reservation & Recorded Income', 'Res ID: 3 | Amount: ₱2,893,730.00', '2026-03-23 09:07:07'),
(5, 1, 'Processed POS Transaction', 'OR: OR-20260323-0002 | Type: INCOME | Amount: ₱234,567.00', '2026-03-23 09:20:32'),
(6, 1, 'Processed POS Transaction', 'OR: OR-20260323-0003 | Type: EXPENSE | Amount: ₱234.00', '2026-03-23 09:20:51'),
(7, 1, 'Exported Transactions to Excel', '', '2026-03-23 14:02:28'),
(8, 1, 'Issued Check Voucher', 'CV: CV-20260323-0001 | Payee: wlfknvkfkedd | Amount: ₱124,567.00', '2026-03-23 14:25:22'),
(9, 1, 'Processed POS Transaction', 'OR: OR-20260323-0004 | Type: EXPENSE | Amount: ₱34,567.00', '2026-03-23 14:26:30'),
(10, 1, 'Processed POS Transaction', 'OR: OR-20260323-0005 | Type: EXPENSE | Amount: ₱65,432.00', '2026-03-23 14:26:49'),
(11, 1, 'Processed POS Transaction', 'OR: OR-20260323-0006 | Type: EXPENSE | Amount: ₱34,567.00', '2026-03-23 14:26:58'),
(12, 1, 'Deleted Property', 'Removed Lot ID: 9 from inventory', '2026-03-23 14:40:36'),
(13, 1, 'Deleted Property', 'Removed Lot ID: 9 from inventory', '2026-03-23 14:43:17'),
(14, 1, 'Deleted User Account', 'Deleted BUYER account (keycm109@gmail.com). ID: 3', '2026-03-23 14:43:34'),
(15, 1, 'Restored Data', 'Restored User Accounts (ID: 3) from Archive.', '2026-03-23 14:46:48'),
(16, 1, 'Deleted User Account', 'Deleted BUYER account (keycm109@gmail.com). ID: 3', '2026-03-23 14:46:56'),
(17, 1, 'Restored Data', 'Restored User Accounts (ID: 3) from Archive.', '2026-03-23 14:47:01'),
(18, 1, 'Restored Data', 'Restored Property Inventory (ID: 9) from Archive.', '2026-03-23 14:47:08'),
(19, 1, 'Deleted Property', 'Removed Lot ID: 9 from inventory', '2026-03-25 05:41:49'),
(20, 1, 'Restored Data', 'Restored Property Inventory (ID: 9) from Archive.', '2026-03-25 05:42:13'),
(21, 1, 'Changed User Role', 'Updated role for keycm109@gmail.com from BUYER to BUYER. ID: 3', '2026-03-27 07:02:33'),
(22, 1, 'Created User Account', 'Created BUYER account for Vincent paul D Pena (penapaul858@gmail.com). ID: 4', '2026-03-27 07:03:12'),
(23, 1, 'Added New Property', 'Lot ID: 10 | Block: 1234, Lot: 2345 | Location: Guagua', '2026-03-27 07:04:48'),
(24, 1, 'Approved Reservation & Recorded Income', 'Res ID: 4 | Amount: ₱808,704.00', '2026-03-27 07:06:35'),
(25, 1, 'Added New Property', 'Lot ID: 11 | Block: 1234, Lot: 2345 | Location: Guagua', '2026-03-27 07:21:09'),
(26, 1, 'Approved Reservation & Recorded Income', 'Res ID: 5 | Amount: ₱8,095,591,062.00', '2026-03-27 07:24:00'),
(51, 1, 'Exported Transactions to Excel', '', '2026-03-29 04:09:38');

-- --------------------------------------------------------

--
-- Table structure for table `delete_history`
--

CREATE TABLE `delete_history` (
  `id` int(11) NOT NULL,
  `module_name` varchar(50) NOT NULL,
  `record_id` int(11) NOT NULL,
  `record_data` text NOT NULL,
  `deleted_by` int(11) NOT NULL,
  `deleted_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `is_hidden` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `delete_history`
--

INSERT INTO `delete_history` (`id`, `module_name`, `record_id`, `record_data`, `deleted_by`, `deleted_at`, `is_hidden`) VALUES
(1, 'Property Inventory', 9, '{\"id\":\"9\",\"location\":\"Guagua\",\"phase_id\":null,\"block_no\":\"1234\",\"lot_no\":\"23\",\"area\":\"2345.00\",\"price_per_sqm\":\"1234.00\",\"total_price\":\"2893730.00\",\"status\":\"SOLD\",\"property_overview\":\"hello\",\"coordinates\":null,\"lot_image\":\"1771232190_6ec38535-efcb-4a1f-9bca-df784b79aac9.jpeg\",\"property_type\":\"Lot\",\"latitude\":\"15.11735676\",\"longitude\":\"120.58329851\"}', 1, '2026-03-23 14:40:36', 0);

-- --------------------------------------------------------

--
-- Table structure for table `lots`
--

CREATE TABLE `lots` (
  `id` int(11) NOT NULL,
  `location` varchar(255) DEFAULT NULL,
  `phase_id` int(11) DEFAULT NULL,
  `block_no` varchar(10) DEFAULT NULL,
  `lot_no` varchar(10) DEFAULT NULL,
  `area` decimal(10,2) DEFAULT NULL,
  `price_per_sqm` decimal(10,2) DEFAULT NULL,
  `total_price` decimal(12,2) DEFAULT NULL,
  `status` enum('AVAILABLE','RESERVED','SOLD') DEFAULT 'AVAILABLE',
  `property_overview` text DEFAULT NULL,
  `coordinates` varchar(50) DEFAULT NULL,
  `lot_image` varchar(255) DEFAULT 'default_lot.jpg',
  `property_type` enum('Subdivision','Lot','Land','Farm','Shop','Business') DEFAULT 'Subdivision',
  `latitude` decimal(10,8) DEFAULT NULL,
  `longitude` decimal(11,8) DEFAULT NULL,
  `points` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `lots`
--

INSERT INTO `lots` (`id`, `location`, `phase_id`, `block_no`, `lot_no`, `area`, `price_per_sqm`, `total_price`, `status`, `property_overview`, `coordinates`, `lot_image`, `property_type`, `latitude`, `longitude`, `points`) VALUES
(1, NULL, 1, 'A', '1', 100.00, 5000.00, 500000.00, 'RESERVED', NULL, '295.6,202 335.7,227.8 255.5,264.1 294.3,292.6', 'default_lot.jpg', 'Subdivision', NULL, NULL, '553.1,367.6 593.3,396.1 551.8,453 515.6,434.9'),
(8, 'ergt', NULL, '12', '132', 13.00, 123.00, 1599.00, 'SOLD', 'qswdefrgthyjukikhmnbvcx', NULL, '1770977471_back.png', '', 14.96326134, 120.63754721, '467.7,314.6 510.4,341.7 422.4,378 469,402.6'),
(9, 'Guagua', NULL, '1234', '23', 2345.00, 1234.00, 2893730.00, 'AVAILABLE', 'hello', '422.4,282.9 463.8,307.5 422.4,377.4 378.4,351.5', '1771232190_6ec38535-efcb-4a1f-9bca-df784b79aac9.jpeg', 'Lot', 15.11735676, 120.58329851, '258.1,176.9 293,197.6 256.8,259.7 215.4,236.4'),
(10, 'Guagua', NULL, '1234', '2345', 234.00, 3456.00, 808704.00, 'SOLD', 'fgh', NULL, '1774595088_20240524_104408.png', 'Lot', NULL, NULL, NULL),
(11, 'Guagua', NULL, '1234', '2345', 234.00, 34596543.00, 8095591062.00, 'SOLD', 'edrftghj', NULL, '1774596069_20240524_101700.png', 'Lot', NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `lot_gallery`
--

CREATE TABLE `lot_gallery` (
  `id` int(11) NOT NULL,
  `lot_id` int(11) DEFAULT NULL,
  `image_path` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `lot_gallery`
--

INSERT INTO `lot_gallery` (`id`, `lot_id`, `image_path`) VALUES
(1, 8, '1770977471_0_618915627_909738964940314_969639640789004154_n.jpg'),
(2, 8, '1770977471_1_621145074_1385022632744250_3609463222790889375_n.jpg'),
(3, 8, '1770977471_2_Gemini_Generated_Image_4i5kcd4i5kcd4i5k.png'),
(5, 10, '1774595088_0_20240524_101700.png'),
(6, 10, '1774595088_1_20240524_101709.png'),
(7, 10, '1774595088_2_20240524_103910.png'),
(8, 11, '1774596069_0_Picture1.jpg'),
(9, 11, '1774596069_1_RIT02096.jpg');

-- --------------------------------------------------------

--
-- Table structure for table `phases`
--

CREATE TABLE `phases` (
  `id` int(11) NOT NULL,
  `name` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `phases`
--

INSERT INTO `phases` (`id`, `name`) VALUES
(1, 'Guagua (Pampanga)'),
(2, 'Minalin (Pampanga)'),
(3, 'Porac'),
(4, 'Lubao'),
(5, 'San Fernando'),
(6, 'Angeles City');

-- --------------------------------------------------------

--
-- Table structure for table `projects`
--

CREATE TABLE `projects` (
  `id` int(11) NOT NULL,
  `name` varchar(150) NOT NULL,
  `status` enum('ACTIVE','COMPLETED') DEFAULT 'ACTIVE'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `projects`
--

INSERT INTO `projects` (`id`, `name`, `status`) VALUES
(1, 'General Operations', 'ACTIVE'),
(2, 'Phase 1 Development', 'ACTIVE');

-- --------------------------------------------------------

--
-- Table structure for table `reservations`
--

CREATE TABLE `reservations` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `contact_number` varchar(20) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `birth_date` date DEFAULT NULL,
  `lot_id` int(11) DEFAULT NULL,
  `reservation_date` datetime DEFAULT current_timestamp(),
  `status` enum('PENDING','APPROVED','CANCELLED') DEFAULT 'PENDING',
  `payment_type` enum('CASH','INSTALLMENT') DEFAULT NULL,
  `installment_months` int(11) DEFAULT NULL,
  `monthly_payment` decimal(12,2) DEFAULT NULL,
  `payment_proof` varchar(255) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `buyer_address` text DEFAULT NULL,
  `valid_id_file` varchar(255) DEFAULT NULL,
  `selfie_with_id` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `reservations`
--

INSERT INTO `reservations` (`id`, `user_id`, `contact_number`, `email`, `birth_date`, `lot_id`, `reservation_date`, `status`, `payment_type`, `installment_months`, `monthly_payment`, `payment_proof`, `notes`, `buyer_address`, `valid_id_file`, `selfie_with_id`) VALUES
(2, 1, '09667785843', NULL, '2001-06-14', 8, '2026-02-13 18:35:35', 'APPROVED', 'CASH', 12, 0.00, '1770978935_621145074_1385022632744250_3609463222790889375_n.jpg', NULL, 'Talang pulungmasle', '1770978935_618915627_909738964940314_969639640789004154_n.jpg', '1770978935_Gemini_Generated_Image_4i5kcd4i5kcd4i5k.png'),
(4, 4, '09663195259', NULL, '2026-03-17', 10, '2026-03-27 15:06:07', 'APPROVED', 'CASH', 12, 53913.60, '1774595167_20240524_103910.png', NULL, 'penapaul858@gmail.com', '1774595167_20240524_101700.png', '1774595167_RIT02096.jpg'),
(5, 4, '09663195259', NULL, '2026-03-17', 11, '2026-03-27 15:23:33', 'APPROVED', 'INSTALLMENT', 24, 269853035.40, '1774596213_20240524_103910.png', NULL, 'penapaul858@gmail.com', '1774596213_20240524_104408.png', '1774596213_20240524_101700.png');

-- --------------------------------------------------------

--
-- Table structure for table `transactions`
--

CREATE TABLE `transactions` (
  `id` int(11) NOT NULL,
  `reservation_id` int(11) DEFAULT NULL,
  `or_number` varchar(50) NOT NULL,
  `transaction_date` date NOT NULL,
  `type` enum('INCOME','EXPENSE') NOT NULL,
  `category_id` int(11) NOT NULL,
  `project_id` int(11) NOT NULL,
  `amount` decimal(12,2) NOT NULL,
  `description` text DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  `payee` varchar(150) DEFAULT NULL,
  `bank_name` varchar(100) DEFAULT NULL,
  `check_number` varchar(50) DEFAULT NULL,
  `is_check` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `transactions`
--

INSERT INTO `transactions` (`id`, `reservation_id`, `or_number`, `transaction_date`, `type`, `category_id`, `project_id`, `amount`, `description`, `user_id`, `payee`, `bank_name`, `check_number`, `is_check`, `created_at`) VALUES
(1, NULL, 'OR-20260323-0001', '2026-03-23', 'INCOME', 8, 1, 2893730.00, 'Payment for Lot (Block 1234 Lot 23) - Res#3', 1, NULL, NULL, NULL, 0, '2026-03-23 09:07:07'),
(2, NULL, 'OR-20260323-0002', '2026-03-23', 'INCOME', 3, 2, 234567.00, 'hrllo', 1, NULL, NULL, NULL, 0, '2026-03-23 09:20:32'),
(3, NULL, 'OR-20260323-0003', '2026-03-23', 'EXPENSE', 1, 1, 234.00, 'hrllo', 1, NULL, NULL, NULL, 0, '2026-03-23 09:20:51'),
(4, NULL, 'CV-20260323-0001', '2026-03-23', 'EXPENSE', 1, 1, 124567.00, 'wlfknvkfkedd', 1, 'wlfknvkfkedd', 'BDO', '234456', 1, '2026-03-23 14:25:22'),
(5, NULL, 'OR-20260323-0004', '2026-03-25', 'EXPENSE', 1, 1, 34567.00, '', 1, NULL, NULL, NULL, 0, '2026-03-23 14:26:30'),
(6, NULL, 'OR-20260323-0005', '2026-03-25', 'EXPENSE', 1, 1, 65432.00, '', 1, NULL, NULL, NULL, 0, '2026-03-23 14:26:49'),
(7, NULL, 'OR-20260323-0006', '2026-03-27', 'EXPENSE', 1, 1, 34567.00, '', 1, NULL, NULL, NULL, 0, '2026-03-23 14:26:58'),
(8, NULL, 'OR-20260327-0001', '2026-03-27', 'INCOME', 8, 1, 808704.00, 'Payment for Lot (Block 1234 Lot 2345) - Res#4', 1, NULL, NULL, NULL, 0, '2026-03-27 07:06:35'),
(9, NULL, 'OR-20260327-0002', '2026-03-27', 'INCOME', 8, 1, 8095591062.00, 'Payment for Lot (Block 1234 Lot 2345) - Res#5', 1, NULL, NULL, NULL, 0, '2026-03-27 07:24:00'),
(19, NULL, '', '2026-03-29', 'INCOME', 0, 0, 100000.00, 'wert', 0, NULL, NULL, NULL, 0, '2026-03-29 05:15:30'),
(22, NULL, '234567890', '2026-03-29', 'INCOME', 0, 0, 1000000.00, 'fgfd', 0, NULL, NULL, NULL, 0, '2026-03-29 05:19:53'),
(24, NULL, '7654', '2026-03-29', 'INCOME', 0, 0, 3456.00, '2345', 0, NULL, NULL, NULL, 0, '2026-03-29 05:22:12'),
(26, 5, '345678', '2026-03-29', 'INCOME', 0, 0, 10938.00, 'Down Payment for Res#5 - Gcash', 0, NULL, NULL, NULL, 0, '2026-03-29 05:55:10'),
(27, 5, '4309345903470-39234', '2026-03-29', 'INCOME', 0, 0, 619107274.40, 'Down Payment for Res#5 - Bank', 0, NULL, NULL, NULL, 0, '2026-03-29 05:56:02'),
(28, 5, '984049476324893353243', '2026-03-29', 'INCOME', 0, 0, 1000000000.00, 'Down Payment for Res#5 - Bank', 0, NULL, NULL, NULL, 0, '2026-03-29 05:57:03'),
(29, 4, '456789098765432', '2026-03-29', 'INCOME', 0, 0, 1610.80, 'Down Payment for Res#4 - Bank', 0, NULL, NULL, NULL, 0, '2026-03-29 06:03:55'),
(30, 4, '456789098765434', '2026-03-31', 'INCOME', 0, 0, 160130.00, 'Down Payment for Res#4 - Gcash', 0, NULL, NULL, NULL, 0, '2026-03-29 06:04:12'),
(31, 2, '3456789', '2026-03-29', 'INCOME', 0, 0, 319.80, 'Down Payment for Res#2 - Gcash', 0, NULL, NULL, NULL, 0, '2026-03-29 06:05:35');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `fullname` varchar(100) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `role` enum('SUPER ADMIN','ADMIN','MANAGER','AGENT','BUYER') DEFAULT 'BUYER',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `fullname`, `email`, `password`, `phone`, `role`, `created_at`) VALUES
(1, 'Super Admin', 'admin@test.com', '0192023a7bbd73250516f069df18b500', NULL, 'ADMIN', '2026-02-10 12:14:01'),
(2, 'Roms', 'admin@gmail.com', '7488e331b8b64e5794da3fa4eb10ad5d', '09667785843', 'BUYER', '2026-03-05 02:49:17'),
(3, 'Vincent paul D Pena', 'keycm109@gmail.com', 'e035f808143d695f233915ce5072c018', '0933 4257317', 'BUYER', '2026-03-23 14:47:01'),
(4, 'Vincent paul D Pena', 'penapaul858@gmail.com', 'a44d52b99eafd5fdd094ad416a295f14', '0933 4257317', 'BUYER', '2026-03-27 07:03:12');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `accounting_categories`
--
ALTER TABLE `accounting_categories`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `audit_logs`
--
ALTER TABLE `audit_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `delete_history`
--
ALTER TABLE `delete_history`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `lots`
--
ALTER TABLE `lots`
  ADD PRIMARY KEY (`id`),
  ADD KEY `phase_id` (`phase_id`);

--
-- Indexes for table `lot_gallery`
--
ALTER TABLE `lot_gallery`
  ADD PRIMARY KEY (`id`),
  ADD KEY `lot_id` (`lot_id`);

--
-- Indexes for table `phases`
--
ALTER TABLE `phases`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `projects`
--
ALTER TABLE `projects`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `reservations`
--
ALTER TABLE `reservations`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `lot_id` (`lot_id`);

--
-- Indexes for table `transactions`
--
ALTER TABLE `transactions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `or_number` (`or_number`),
  ADD KEY `reservation_id` (`reservation_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `accounting_categories`
--
ALTER TABLE `accounting_categories`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT for table `audit_logs`
--
ALTER TABLE `audit_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=52;

--
-- AUTO_INCREMENT for table `delete_history`
--
ALTER TABLE `delete_history`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `lots`
--
ALTER TABLE `lots`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT for table `lot_gallery`
--
ALTER TABLE `lot_gallery`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `phases`
--
ALTER TABLE `phases`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `projects`
--
ALTER TABLE `projects`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `reservations`
--
ALTER TABLE `reservations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `transactions`
--
ALTER TABLE `transactions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=32;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `lots`
--
ALTER TABLE `lots`
  ADD CONSTRAINT `lots_ibfk_1` FOREIGN KEY (`phase_id`) REFERENCES `phases` (`id`);

--
-- Constraints for table `lot_gallery`
--
ALTER TABLE `lot_gallery`
  ADD CONSTRAINT `lot_gallery_ibfk_1` FOREIGN KEY (`lot_id`) REFERENCES `lots` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `reservations`
--
ALTER TABLE `reservations`
  ADD CONSTRAINT `reservations_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  ADD CONSTRAINT `reservations_ibfk_2` FOREIGN KEY (`lot_id`) REFERENCES `lots` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
