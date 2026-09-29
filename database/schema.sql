CREATE DATABASE IF NOT EXISTS network_monitor
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE network_monitor;

CREATE TABLE capture_sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    interface_name VARCHAR(100) NOT NULL,
    started_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    ended_at DATETIME(6) NULL,
    status ENUM('running', 'completed', 'failed', 'interrupted') NOT NULL DEFAULT 'running',
    packets_captured BIGINT UNSIGNED NOT NULL DEFAULT 0,

    INDEX idx_session_started (started_at),
    INDEX idx_session_status (status)
);

CREATE TABLE packets (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    session_id BIGINT UNSIGNED NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    size_bytes INT UNSIGNED NOT NULL,
    source_port SMALLINT UNSIGNED NULL,
    destination_port SMALLINT UNSIGNED NULL,
    captured_at DATETIME(6) NOT NULL,

    CONSTRAINT fk_packet_session
        FOREIGN KEY (session_id)
        REFERENCES capture_sessions(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    INDEX idx_session_src (session_id, source_ip),
    INDEX idx_session_dst (session_id, destination_ip),
    INDEX idx_session_proto (session_id, protocol)
);