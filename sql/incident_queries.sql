-- Cybersecurity Incident Risk Analysis Queries
-- Comprehensive SQL queries for threat detection and risk analysis

-- ===========================================
-- INCIDENT TRENDS ANALYSIS
-- ===========================================

-- Daily incident frequency trends
SELECT
    DATE(timestamp) as incident_date,
    COUNT(*) as total_incidents,
    COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity = 'High' THEN 1 END) as high_count,
    COUNT(CASE WHEN severity = 'Medium' THEN 1 END) as medium_count,
    COUNT(CASE WHEN severity = 'Low' THEN 1 END) as low_count
FROM incidents
GROUP BY DATE(timestamp)
ORDER BY incident_date;

-- Hourly incident patterns (identify peak attack times)
SELECT
    strftime('%H', timestamp) as hour_of_day,
    COUNT(*) as incident_count,
    AVG(CASE
        WHEN severity = 'Critical' THEN 4
        WHEN severity = 'High' THEN 3
        WHEN severity = 'Medium' THEN 2
        WHEN severity = 'Low' THEN 1
        ELSE 0 END) as avg_severity_score
FROM incidents
GROUP BY hour_of_day
ORDER BY hour_of_day;

-- Weekly trends
SELECT
    strftime('%Y-%W', timestamp) as week,
    COUNT(*) as weekly_incidents,
    COUNT(DISTINCT source_ip) as unique_attackers,
    AVG(CASE
        WHEN severity = 'Critical' THEN 4
        WHEN severity = 'High' THEN 3
        WHEN severity = 'Medium' THEN 2
        WHEN severity = 'Low' THEN 1
        ELSE 0 END) as avg_severity
FROM incidents
GROUP BY week
ORDER BY week;

-- ===========================================
-- ATTACK FREQUENCY BY EVENT TYPE
-- ===========================================

-- Event type frequency and success rates
SELECT
    event_type,
    COUNT(*) as total_events,
    COUNT(CASE WHEN status = 'Successful' THEN 1 END) as successful_attempts,
    ROUND(CAST(COUNT(CASE WHEN status = 'Successful' THEN 1 END) AS FLOAT) / COUNT(*), 3) as success_rate,
    AVG(CASE
        WHEN severity = 'Critical' THEN 4
        WHEN severity = 'High' THEN 3
        WHEN severity = 'Medium' THEN 2
        WHEN severity = 'Low' THEN 1
        ELSE 0 END) as avg_severity
FROM incidents
GROUP BY event_type
ORDER BY total_events DESC;

-- Event type trends over time
SELECT
    DATE(timestamp) as date,
    event_type,
    COUNT(*) as daily_count,
    SUM(CASE WHEN status = 'Successful' THEN 1 ELSE 0 END) as successful_count
FROM incidents
GROUP BY date, event_type
ORDER BY date, event_type;

-- ===========================================
-- SEVERITY DISTRIBUTIONS
-- ===========================================

-- Overall severity distribution
SELECT
    severity,
    COUNT(*) as count,
    ROUND(CAST(COUNT(*) AS FLOAT) / (SELECT COUNT(*) FROM incidents), 3) as percentage,
    COUNT(DISTINCT source_ip) as unique_ips,
    COUNT(DISTINCT location) as unique_locations
FROM incidents
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'Critical' THEN 4
        WHEN 'High' THEN 3
        WHEN 'Medium' THEN 2
        WHEN 'Low' THEN 1
    END DESC;

-- Severity by event type
SELECT
    event_type,
    severity,
    COUNT(*) as count,
    ROUND(CAST(COUNT(*) AS FLOAT) / SUM(COUNT(*)) OVER (PARTITION BY event_type), 3) as severity_percentage
FROM incidents
GROUP BY event_type, severity
ORDER BY event_type,
    CASE severity
        WHEN 'Critical' THEN 4
        WHEN 'High' THEN 3
        WHEN 'Medium' THEN 2
        WHEN 'Low' THEN 1
    END DESC;

-- ===========================================
-- TOP ATTACKER IPS ANALYSIS
-- ===========================================

-- Top attacking IPs by incident count
SELECT
    source_ip,
    COUNT(*) as total_incidents,
    COUNT(DISTINCT event_type) as unique_event_types,
    MAX(severity) as max_severity,
    COUNT(CASE WHEN status = 'Successful' THEN 1 END) as successful_attacks,
    ROUND(CAST(COUNT(CASE WHEN status = 'Successful' THEN 1 END) AS FLOAT) / COUNT(*), 3) as success_rate,
    GROUP_CONCAT(DISTINCT location) as locations,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen
FROM incidents
GROUP BY source_ip
ORDER BY total_incidents DESC
LIMIT 20;

-- Most persistent attackers (attacks over multiple days)
SELECT
    source_ip,
    COUNT(DISTINCT DATE(timestamp)) as active_days,
    COUNT(*) as total_incidents,
    AVG(CASE
        WHEN severity = 'Critical' THEN 4
        WHEN severity = 'High' THEN 3
        WHEN severity = 'Medium' THEN 2
        WHEN severity = 'Low' THEN 1
        ELSE 0 END) as avg_severity
FROM incidents
GROUP BY source_ip
HAVING active_days > 1
ORDER BY active_days DESC, total_incidents DESC
LIMIT 15;

-- ===========================================
-- RISK SCORING ANALYSIS
-- ===========================================

-- Risk score calculation: severity_weight × incident_frequency
-- Severity weights: Critical=4, High=3, Medium=2, Low=1
WITH severity_weights AS (
    SELECT
        source_ip,
        COUNT(*) as incident_frequency,
        AVG(CASE
            WHEN severity = 'Critical' THEN 4
            WHEN severity = 'High' THEN 3
            WHEN severity = 'Medium' THEN 2
            WHEN severity = 'Low' THEN 1
            ELSE 0 END) as avg_severity_weight,
        COUNT(DISTINCT event_type) as event_type_diversity,
        COUNT(DISTINCT DATE(timestamp)) as persistence_days,
        MAX(timestamp) as last_incident
    FROM incidents
    GROUP BY source_ip
)
SELECT
    source_ip,
    incident_frequency,
    ROUND(avg_severity_weight, 2) as severity_weight,
    ROUND(incident_frequency * avg_severity_weight, 2) as risk_score,
    event_type_diversity,
    persistence_days,
    CASE
        WHEN ROUND(incident_frequency * avg_severity_weight, 2) >= 50 THEN 'Critical'
        WHEN ROUND(incident_frequency * avg_severity_weight, 2) >= 25 THEN 'High'
        WHEN ROUND(incident_frequency * avg_severity_weight, 2) >= 10 THEN 'Medium'
        ELSE 'Low'
    END as risk_level,
    last_incident
FROM severity_weights
ORDER BY risk_score DESC
LIMIT 25;

-- Geographic risk analysis
SELECT
    location,
    COUNT(*) as total_incidents,
    COUNT(DISTINCT source_ip) as unique_attackers,
    AVG(CASE
        WHEN severity = 'Critical' THEN 4
        WHEN severity = 'High' THEN 3
        WHEN severity = 'Medium' THEN 2
        WHEN severity = 'Low' THEN 1
        ELSE 0 END) as avg_severity,
    COUNT(CASE WHEN status = 'Successful' THEN 1 END) as successful_attacks,
    ROUND(CAST(COUNT(CASE WHEN status = 'Successful' THEN 1 END) AS FLOAT) / COUNT(*), 3) as success_rate
FROM incidents
WHERE location IS NOT NULL AND location != 'Unknown'
GROUP BY location
ORDER BY total_incidents DESC;

-- ===========================================
-- CORRELATION ANALYSIS
-- ===========================================

-- Failed logins vs security incidents by IP
SELECT
    COALESCE(i.source_ip, l.ip_address) as ip_address,
    COUNT(DISTINCT CASE WHEN l.success = 'No' THEN l.login_id END) as failed_logins,
    COUNT(DISTINCT i.event_id) as security_incidents,
    COUNT(DISTINCT CASE WHEN l.success = 'No' THEN DATE(l.login_time) END) as failed_login_days,
    COUNT(DISTINCT DATE(i.timestamp)) as incident_days
FROM incidents i
FULL OUTER JOIN logins l ON i.source_ip = l.ip_address
GROUP BY COALESCE(i.source_ip, l.ip_address)
HAVING failed_logins > 0 OR security_incidents > 0
ORDER BY failed_logins DESC, security_incidents DESC
LIMIT 20;

-- Device targeting patterns
SELECT
    destination_device,
    COUNT(*) as total_incidents,
    COUNT(DISTINCT source_ip) as unique_attackers,
    COUNT(DISTINCT event_type) as unique_event_types,
    GROUP_CONCAT(DISTINCT severity) as severities_seen,
    MIN(timestamp) as first_attack,
    MAX(timestamp) as last_attack
FROM incidents
GROUP BY destination_device
ORDER BY total_incidents DESC;
