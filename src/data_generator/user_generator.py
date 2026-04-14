"""
Génération des profils utilisateurs - Zero Trust Policy Agent
"""

import random
import json
import os
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

# Coordonnées GPS des villes supportées
CITIES = {
    "Tunis":     (36.8065,  10.1815),
    "Paris":     (48.8566,   2.3522),
    "London":    (51.5074,  -0.1278),
    "Berlin":    (52.5200,  13.4050),
    "Madrid":    (40.4168,  -3.7038),
    "Rome":      (41.9028,  12.4964),
    "Barcelona": (41.3851,   2.1734),
    "Milan":     (45.4642,   9.1900),
}

# Devices courants par profil utilisateur
COMMON_DEVICES = ["windows", "mac", "linux", "mobile"]

# Départements d'une organisation type
DEPARTMENTS = ["IT", "HR", "Sales", "Marketing", "Finance", "R&D", "Legal", "Operations"]


def generate_user_profiles(n_users=100):
    """
    Génère des profils utilisateurs réalistes.

    Args:
        n_users (int): nombre d'utilisateurs à générer

    Returns:
        list[dict]: liste des profils utilisateurs
    """
    users = []

    for i in range(n_users):
        city = random.choice(list(CITIES.keys()))
        lat, lon = CITIES[city]

        # Chaque utilisateur utilise 1 à 3 devices habituels
        usual_devices = random.sample(COMMON_DEVICES, k=random.randint(1, 3))

        user = {
            "user_id":         f"user_{i + 1:03d}",
            "email":           fake.email(),
            "name":            fake.name(),
            "department":      random.choice(DEPARTMENTS),
            "usual_location":  city,
            "usual_lat":       lat,
            "usual_lon":       lon,
            "usual_hours":     list(range(9, 19)),      # 9h–18h
            "usual_devices":   usual_devices,
            "risk_score":      round(random.uniform(0.0, 1.0), 2),
            "created_at":      (
                datetime.now() - timedelta(days=random.randint(30, 730))
            ).isoformat(),
        }
        users.append(user)

    return users


def save_user_profiles(users, filepath):
    """
    Sauvegarde les profils utilisateurs au format JSON.

    Args:
        users (list[dict]): liste des profils
        filepath (str): chemin de destination

    Returns:
        list[dict]: la même liste (pour chaînage)
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, default=str, ensure_ascii=False)
    print(f"✅ {len(users)} profils utilisateurs sauvegardés dans {filepath}")
    return users