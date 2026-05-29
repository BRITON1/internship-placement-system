create database INTERNHUB;
-- Ensure we are using the correct database
USE INTERNHUB;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('student', 'organization', 'supervisor', 'admin') NOT NULL,
    status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'approved',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Internships/Placements Table
CREATE TABLE IF NOT EXISTS placements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    organization_id INT,
    status ENUM('open', 'filled', 'closed') DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Audit Logs Table (For your log_action function)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(255),
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


USE INTERNHUB;

-- Fix the 'Unknown column user_email' error
ALTER TABLE audit_logs ADD COLUMN user_email VARCHAR(100) AFTER id;

-- Fix the 'Unknown column activity_date' error
ALTER TABLE audit_logs ADD COLUMN activity_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Double check: Ensure the log_action logic can actually save
ALTER TABLE audit_logs MODIFY COLUMN details TEXT;
