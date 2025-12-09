-- Cybersecurity Incident Risk Analysis Database Schema
-- Create tables for incidents and login activity data

-- Create incidents table
CREATE TABLE incidents (
    event_id INTEGER PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    source_ip VARCHAR(45) NOT NULL, -- IPv4/IPv6 support
    destination_device VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('Successful', 'Failed', 'Blocked', 'Allowed')),
    location VARCHAR(50)
);

-- Create logins table
CREATE TABLE logins (
    login_id INTEGER PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    login_time DATETIME NOT NULL,
    success VARCHAR(3) NOT NULL CHECK (success IN ('Yes', 'No')),
    ip_address VARCHAR(45) NOT NULL
);

-- Create indexes for performance on common query patterns
CREATE INDEX idx_incidents_timestamp ON incidents(timestamp);
CREATE INDEX idx_incidents_event_type ON incidents(event_type);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_source_ip ON incidents(source_ip);
CREATE INDEX idx_incidents_location ON incidents(location);

CREATE INDEX idx_logins_user_id ON logins(user_id);
CREATE INDEX idx_logins_login_time ON logins(login_time);
CREATE INDEX idx_logins_success ON logins(success);
CREATE INDEX idx_logins_ip_address ON logins(ip_address);

-- Optional: Create a view for combined incident and login analysis
CREATE VIEW security_events AS
SELECT
    'incident' as event_category,
    i.event_id as event_id,
    i.timestamp,
    i.event_type,
    i.severity,
    i.source_ip,
    i.destination_device,
    i.status,
    i.location,
    NULL as user_id,
    NULL as login_success
FROM incidents i
UNION ALL
SELECT
    'login' as event_category,
    l.login_id as event_id,
    l.login_time as timestamp,
    CASE WHEN l.success = 'No' THEN 'Failed Login' ELSE 'Successful Login' END as event_type,
    CASE WHEN l.success = 'No' THEN 'Medium' ELSE 'Low' END as severity,
    l.ip_address as source_ip,
    NULL as destination_device,
    l.success as status,
    NULL as location,
    l.user_id,
    l.success as login_success
FROM logins l;
