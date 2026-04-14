"""
Génération des scénarios d'attaque - Zero Trust Policy Agent

Chaque fonction génère UNE liste de logs représentant un scénario d'attaque.
Tous les logs retournés comptent pour 1 seul "slot" d'attaque dans le quota.
"""

import random
from datetime import datetime, timedelta
from config import THRESHOLDS, SUSPICIOUS_DEVICES
from user_generator import CITIES


def _random_ip(prefix):
    """Génère une adresse IP aléatoire avec le préfixe donné."""
    return f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_bruteforce_logs(user_id, base_time, n_attempts=None):
    """
    Génère un scénario de brute-force :
    plusieurs tentatives de connexion échouées en rafale,
    suivies optionnellement d'un succès.

    Args:
        user_id (str): identifiant de l'utilisateur cible
        base_time (datetime): moment de début de l'attaque
        n_attempts (int): nombre de tentatives (défaut : 5-8)

    Returns:
        list[dict]: logs du scénario (entre 5 et 9 entrées)
    """
    if n_attempts is None:
        n_attempts = random.randint(5, 8)

    attacker_ip = _random_ip("45")
    logs = []

    # Tentatives échouées
    for i in range(n_attempts):
        logs.append({
            "user_id":      user_id,
            "timestamp":    base_time + timedelta(seconds=i * random.randint(1, 4)),
            "ip_address":   attacker_ip,
            "location":     "Unknown",
            "success":      False,
            "auth_method":  "password",
            "device_type":  random.choice(["windows", "linux"]),
            "is_attack":    True,
            "attack_type":  "bruteforce",
        })

    # Dernière tentative parfois réussie (accès compromis)
    if random.random() < 0.3:
        logs.append({
            "user_id":      user_id,
            "timestamp":    base_time + timedelta(seconds=n_attempts * 3),
            "ip_address":   attacker_ip,
            "location":     "Unknown",
            "success":      True,
            "auth_method":  "password",
            "device_type":  "linux",
            "is_attack":    True,
            "attack_type":  "bruteforce",
        })

    return logs


def generate_impossible_travel_logs(user_id, base_time, city1="Tunis", city2="Paris"):
    """
    Génère un scénario de voyage impossible :
    deux connexions depuis des villes distantes séparées de seulement 30 min.

    Args:
        user_id (str): identifiant de l'utilisateur
        base_time (datetime): moment de la première connexion
        city1 (str): ville de la première connexion
        city2 (str): ville de la seconde connexion (doit être dans CITIES)

    Returns:
        list[dict]: 2 logs (un par ville)
    """
    # Fallback si les villes ne sont pas dans le dictionnaire
    if city1 not in CITIES:
        city1 = "Tunis"
    if city2 not in CITIES:
        city2 = "Paris"

    # S'assurer que les deux villes sont différentes
    if city1 == city2:
        city2 = next(c for c in CITIES if c != city1)

    logs = [
        {
            "user_id":      user_id,
            "timestamp":    base_time,
            "ip_address":   _random_ip("197"),
            "location":     city1,
            "success":      True,
            "auth_method":  "password",
            "device_type":  "mobile",
            "is_attack":    True,
            "attack_type":  "impossible_travel",
        },
        {
            "user_id":      user_id,
            "timestamp":    base_time + timedelta(minutes=THRESHOLDS["min_travel_minutes"]),
            "ip_address":   _random_ip("80"),
            "location":     city2,
            "success":      True,
            "auth_method":  "password",
            "device_type":  "mobile",
            "is_attack":    True,
            "attack_type":  "impossible_travel",
        },
    ]
    return logs


def generate_unusual_hour_logs(user_id, base_time):
    """
    Génère un log de connexion à une heure inhabituelle
    (plage nocturne définie dans THRESHOLDS).

    Args:
        user_id (str): identifiant de l'utilisateur
        base_time (datetime): date de base (l'heure sera remplacée)

    Returns:
        list[dict]: 1 log
    """
    unusual_hour = random.choice(THRESHOLDS["unusual_hours"])
    unusual_time = base_time.replace(
        hour=unusual_hour,
        minute=random.randint(0, 59),
        second=random.randint(0, 59),
    )

    return [{
        "user_id":      user_id,
        "timestamp":    unusual_time,
        "ip_address":   _random_ip("192.168"),
        "location":     "Unknown",
        "success":      random.random() > 0.4,
        "auth_method":  "password",
        "device_type":  random.choice(["windows", "mobile"]),
        "is_attack":    True,
        "attack_type":  "unusual_hour",
    }]


def generate_new_device_logs(user_id, base_time, usual_devices):
    """
    Génère un log de connexion depuis un appareil inconnu.

    Args:
        user_id (str): identifiant de l'utilisateur
        base_time (datetime): moment de la connexion
        usual_devices (list[str]): appareils habituels de l'utilisateur

    Returns:
        list[dict]: 1 log
    """
    # Appareils suspects qui ne sont pas déjà utilisés par cet utilisateur
    candidates = [d for d in SUSPICIOUS_DEVICES if d not in usual_devices]

    # Fallback : si tous les suspects sont déjà connus, on prend quand même un suspect
    if not candidates:
        candidates = SUSPICIOUS_DEVICES

    new_device = random.choice(candidates)

    return [{
        "user_id":      user_id,
        "timestamp":    base_time,
        "ip_address":   _random_ip("10.0"),
        "location":     "Unknown",
        "success":      True,
        "auth_method":  "password",
        "device_type":  new_device,
        "is_attack":    True,
        "attack_type":  "new_device",
    }]
