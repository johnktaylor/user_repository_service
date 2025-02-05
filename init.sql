-- Create the userrepo database if it doesn't exist
CREATE DATABASE IF NOT EXISTS userrepo;

USE userrepo;

-- Users table to store basic user information
CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    user_type ENUM('human', 'machine') NOT NULL,
    expiry_date TIMESTAMP,
    UNIQUE (username)
);

CREATE TABLE IF NOT EXISTS user_details (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    details JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id)
);

-- WebAuthn credentials table for storing authentication data
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    credential_id VARBINARY(255) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count INT DEFAULT 0,
    transports VARCHAR(255),
    attestation_format VARCHAR(50),
    credential_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL,
    counter_last_updated TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- OpenID sign-ins table for storing OpenID authentication data
CREATE TABLE IF NOT EXISTS oauth2_signins (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    name VARCHAR(50) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    openid_identifier VARCHAR(255) NOT NULL,
    access_token VARCHAR(500),
    refresh_token VARCHAR(500),
    token_expires_at TIMESTAMP,
    scopes VARCHAR(255),
    id_token TEXT,
    last_refreshed TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, name),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Public SSH keys table for storing user's SSH keys
CREATE TABLE IF NOT EXISTS public_ssh_keys (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    name VARCHAR(50) NOT NULL,
    ssh_key TEXT NOT NULL,
    key_type VARCHAR(20) NOT NULL,
    fingerprint VARCHAR(255) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL,
    expiry_date TIMESTAMP,
    UNIQUE (user_id, name),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Login tokens table for managing user session tokens
CREATE TABLE IF NOT EXISTS login_tokens (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    token CHAR(64) NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (token),
    INDEX idx_token (token)
);

-- Passwords table for storing user password hashes
CREATE TABLE IF NOT EXISTS passwords (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    expiry_date TIMESTAMP,  -- Changed from DATE to TIMESTAMP
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add additional checks or alter statements if needed
-- Example: ALTER TABLE user ADD COLUMN IF NOT EXISTS new_column VARCHAR(50);
