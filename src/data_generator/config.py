"""
Configuration du générateur de logs - Zero Trust Policy Agent
"""

import os

# Configuration des chemins
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


os.makedirs(DATA_DIR, exist_ok=True)

# Configuration des logs
LOG_CONFIG = {
    "total_logs": 5000,
    "days_back": 30,
    "attack_ratio": 0.20,   # 20% d'attaques
    "batch_size": 100
}

# Configuration des utilisateurs
USER_CONFIG = {
    "min_users": 50,
    "max_users": 150,
    "default_users": 100
}

# Configuration des IPs par région
IP_RANGES = {
    "tunis":    ("197.0.0.0",   "197.27.255.255"),
    "france":   ("80.12.0.0",   "80.15.255.255"),
    "germany":  ("79.240.0.0",  "79.255.255.255"),
    "uk":       ("81.128.0.0",  "81.159.255.255"),
    "unknown":  ("45.0.0.0",    "45.255.255.255"),
}

# Horaires normaux de travail (9h-18h)
NORMAL_HOURS = list(range(9, 19))

# Seuils de détection
THRESHOLDS = {
    "max_failed_attempts": 5,       # brute force
    "min_distance_km": 500,          # impossible travel
    "unusual_hour_start": 22,        # heure suspecte début
    "unusual_hour_end": 6,           # heure suspecte fin
    "unusual_hours": [22, 23, 0, 1, 2, 3, 4, 5],  # plage complète
    "min_travel_minutes": 30,        # délai minimum entre deux locations distantes
}

# Types d'attaques disponibles
ATTACK_TYPES = ["bruteforce", "impossible_travel", "unusual_hour", "new_device"]

# Devices connus pour les nouveaux appareils suspects
SUSPICIOUS_DEVICES = ["raspberry_pi", "unknown_android", "new_iphone", "kali_linux", "unknown_device"]