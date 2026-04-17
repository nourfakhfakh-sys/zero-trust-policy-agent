SELECT 
    COUNT(*) as total_logs,
    SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as failed,
    SUM(CASE WHEN is_attack THEN 1 ELSE 0 END) as attacks,
    ROUND(SUM(CASE WHEN is_attack THEN 1 ELSE 0 END)::numeric / COUNT(*) * 100, 2) as attack_percentage
FROM auth_logs;