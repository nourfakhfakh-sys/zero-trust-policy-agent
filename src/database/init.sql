-- ============================================================================
-- SCHÉMA DE BASE DE DONNÉES - ZERO TRUST POLICY AGENT
-- ============================================================================

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(50) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100),
    department VARCHAR(50),
    usual_location VARCHAR(100),
    usual_lat FLOAT,
    usual_lon FLOAT,
    usual_hours JSONB,
    usual_devices JSONB,
    risk_score FLOAT DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table des logs d'authentification
CREATE TABLE IF NOT EXISTS auth_logs (
    log_id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) REFERENCES users(user_id),
    timestamp TIMESTAMP NOT NULL,
    ip_address INET,
    location VARCHAR(100),
    success BOOLEAN NOT NULL,
    auth_method VARCHAR(50),
    device_type VARCHAR(50),
    is_attack BOOLEAN DEFAULT FALSE,
    attack_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table des décisions
CREATE TABLE IF NOT EXISTS decisions (
    decision_id SERIAL PRIMARY KEY,
    log_id INTEGER REFERENCES auth_logs(log_id),
    user_id VARCHAR(50) REFERENCES users(user_id),
    decision VARCHAR(20) NOT NULL,
    confidence_score FLOAT,
    rule_triggered VARCHAR(100),
    ml_score FLOAT,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Table des anomalies
CREATE TABLE IF NOT EXISTS anomalies (
    anomaly_id SERIAL PRIMARY KEY,
    log_id INTEGER REFERENCES auth_logs(log_id),
    user_id VARCHAR(50) REFERENCES users(user_id),
    anomaly_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20),
    details JSONB,
    detected_at TIMESTAMP DEFAULT NOW()
);

-- Index
CREATE INDEX IF NOT EXISTS idx_auth_logs_timestamp ON auth_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_logs_user_id ON auth_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_logs_is_attack ON auth_logs(is_attack);

-- Vue statistiques
CREATE OR REPLACE VIEW user_statistics AS
SELECT 
    u.user_id,
    u.email,
    u.name,
    COUNT(al.log_id) as total_logins,
    SUM(CASE WHEN al.success THEN 1 ELSE 0 END) as successful_logins,
    SUM(CASE WHEN al.is_attack THEN 1 ELSE 0 END) as attacks_detected
FROM users u
LEFT JOIN auth_logs al ON u.user_id = al.user_id
GROUP BY u.user_id, u.email, u.name;