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
    usual_hours JSONB,           -- Horaires habituels (ex: [9,10,11,...,18])
    usual_devices JSONB,          -- Devices habituels (ex: ["windows", "mobile"])
    risk_score FLOAT DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table des logs d'authentification
CREATE TABLE IF NOT EXISTS auth_logs (
    log_id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) REFERENCES users(user_id),
    timestamp TIMESTAMP NOT NULL,
    ip_address INET,              -- Type spécial PostgreSQL pour IP
    location VARCHAR(100),
    latitude FLOAT,
    longitude FLOAT,
    success BOOLEAN NOT NULL,
    auth_method VARCHAR(50),      -- password, mfa, biometric
    device_type VARCHAR(50),
    is_attack BOOLEAN DEFAULT FALSE,
    attack_type VARCHAR(50),      -- bruteforce, impossible_travel, etc.
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table des décisions de l'agent Zero Trust
CREATE TABLE IF NOT EXISTS decisions (
    decision_id SERIAL PRIMARY KEY,
    log_id INTEGER REFERENCES auth_logs(log_id),
    user_id VARCHAR(50) REFERENCES users(user_id),
    decision VARCHAR(20) NOT NULL,  -- ALLOW, MFA, BLOCK
    confidence_score FLOAT,          -- Score de confiance (0-1)
    rule_triggered VARCHAR(100),     -- Règle qui a déclenché la décision
    ml_score FLOAT,                  -- Score du modèle ML
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Table pour l'historique des anomalies détectées
CREATE TABLE IF NOT EXISTS anomalies (
    anomaly_id SERIAL PRIMARY KEY,
    log_id INTEGER REFERENCES auth_logs(log_id),
    user_id VARCHAR(50) REFERENCES users(user_id),
    anomaly_type VARCHAR(50) NOT NULL,  -- Type d'anomalie détecté
    severity VARCHAR(20),                -- low, medium, high, critical
    details JSONB,                       -- Détails supplémentaires
    detected_at TIMESTAMP DEFAULT NOW()
);

-- ============================================================================
-- INDEX POUR PERFORMANCES
-- ============================================================================

-- Index sur timestamp pour les requêtes temporelles
CREATE INDEX IF NOT EXISTS idx_auth_logs_timestamp ON auth_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_logs_user_id ON auth_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_logs_is_attack ON auth_logs(is_attack);
CREATE INDEX IF NOT EXISTS idx_auth_logs_attack_type ON auth_logs(attack_type);

-- Index sur user_id pour les jointures rapides
CREATE INDEX IF NOT EXISTS idx_decisions_user_id ON decisions(user_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_user_id ON anomalies(user_id);

-- ============================================================================
-- VUES UTILES
-- ============================================================================

-- Vue : Statistiques par utilisateur
CREATE OR REPLACE VIEW user_statistics AS
SELECT 
    u.user_id,
    u.email,
    u.name,
    COUNT(al.log_id) as total_logins,
    SUM(CASE WHEN al.success THEN 1 ELSE 0 END) as successful_logins,
    SUM(CASE WHEN NOT al.success THEN 1 ELSE 0 END) as failed_logins,
    SUM(CASE WHEN al.is_attack THEN 1 ELSE 0 END) as attacks_detected,
    MAX(al.timestamp) as last_login
FROM users u
LEFT JOIN auth_logs al ON u.user_id = al.user_id
GROUP BY u.user_id, u.email, u.name;

-- Vue : Logs suspects récents (dernières 24h)
CREATE OR REPLACE VIEW recent_suspicious_logs AS
SELECT 
    al.*,
    u.email,
    u.name
FROM auth_logs al
JOIN users u ON al.user_id = u.user_id
WHERE al.is_attack = TRUE
  AND al.timestamp > NOW() - INTERVAL '24 hours'
ORDER BY al.timestamp DESC;

-- ============================================================================
-- FONCTIONS UTILES
-- ============================================================================

-- Fonction : Compter les échecs de connexion sur 5 minutes
CREATE OR REPLACE FUNCTION count_failed_attempts(
    p_user_id VARCHAR(50),
    p_timestamp TIMESTAMP
)
RETURNS INTEGER AS $$
BEGIN
    RETURN (
        SELECT COUNT(*)
        FROM auth_logs
        WHERE user_id = p_user_id
          AND success = FALSE
          AND timestamp BETWEEN p_timestamp - INTERVAL '5 minutes' AND p_timestamp
    );
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- DONNÉES DE TEST (optionnel)
-- ============================================================================

-- Insérer un utilisateur de test
INSERT INTO users (user_id, email, name, department, usual_location, usual_lat, usual_lon, usual_hours, usual_devices)
VALUES (
    'test_user_001',
    'test@example.com',
    'Test User',
    'IT',
    'Tunis',
    36.8065,
    10.1815,
    '[9,10,11,12,13,14,15,16,17,18]'::jsonb,
    '["windows", "mobile"]'::jsonb
)
ON CONFLICT (user_id) DO NOTHING;

COMMIT;
