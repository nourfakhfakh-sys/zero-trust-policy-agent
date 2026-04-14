"""
Script principal - Générateur de logs synthétiques
Zero Trust Policy Agent

Usage :
    python src/data_generator/main_generator.py
"""

import random
import os
import sys
import time
import pandas as pd
from datetime import datetime, timedelta

# -- Path setup : ajoute le dossier courant au sys.path UNE SEULE FOIS --------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)
# -----------------------------------------------------------------------------

from config import LOG_CONFIG, DATA_DIR, ATTACK_TYPES
from user_generator import generate_user_profiles, save_user_profiles
from attack_generator import (
    generate_bruteforce_logs,
    generate_impossible_travel_logs,
    generate_unusual_hour_logs,
    generate_new_device_logs,
)
from utils import save_json, save_csv, print_separator


# ---------------------------------------------------------------------------
# Génération des logs normaux
# ---------------------------------------------------------------------------

def generate_normal_logs(user_profile, start_date, end_date, n_logs):
    """
    Génère des logs de comportement normal pour un utilisateur.

    Args:
        user_profile (dict): profil de l'utilisateur
        start_date (datetime): début de la période
        end_date (datetime): fin de la période
        n_logs (int): nombre de logs à générer

    Returns:
        list[dict]: logs normaux
    """
    logs = []
    user_id      = user_profile["user_id"]
    usual_hours  = user_profile["usual_hours"]
    usual_devs   = user_profile["usual_devices"]
    location     = user_profile["usual_location"]
    delta_days   = (end_date - start_date).days or 1

    for _ in range(n_logs):
        hour      = random.choice(usual_hours)
        timestamp = start_date + timedelta(
            days=random.randint(0, delta_days),
            hours=hour,
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        logs.append({
            "user_id":      user_id,
            "timestamp":    timestamp,
            "ip_address":   f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "location":     location,
            "success":      random.random() > 0.05,          # 95 % succès
            "auth_method":  random.choice(["password", "mfa", "biometric"]),
            "device_type":  random.choice(usual_devs),
            "is_attack":    False,
            "attack_type":  None,
        })

    return logs


# ---------------------------------------------------------------------------
# Génération des logs d'attaque avec quota strict
# ---------------------------------------------------------------------------

def generate_attack_logs(users, n_attack_logs, start_date, days_back):
    """
    Génère exactement n_attack_logs logs d'attaque en respectant
    le quota strict (les scénarios multi-logs comme brute-force ne
    dépassent pas le total demandé).

    Args:
        users (list[dict]): profils utilisateurs
        n_attack_logs (int): nombre exact de logs d'attaque voulu
        start_date (datetime): début de la période
        days_back (int): durée de la période en jours

    Returns:
        list[dict]: logs d'attaque
    """
    attack_logs = []
    max_iterations = n_attack_logs * 20   # garde-fou contre boucle infinie

    for _ in range(max_iterations):
        if len(attack_logs) >= n_attack_logs:
            break

        user        = random.choice(users)
        base_time   = start_date + timedelta(days=random.randint(0, days_back))
        attack_type = random.choice(ATTACK_TYPES)

        if attack_type == "bruteforce":
            # Limite les tentatives pour ne pas exploser le quota
            remaining = n_attack_logs - len(attack_logs)
            max_att   = min(8, remaining)
            if max_att < 2:
                continue
            logs = generate_bruteforce_logs(
                user["user_id"], base_time,
                n_attempts=random.randint(2, max_att)
            )
        elif attack_type == "impossible_travel":
            logs = generate_impossible_travel_logs(
                user["user_id"], base_time
            )
        elif attack_type == "unusual_hour":
            logs = generate_unusual_hour_logs(user["user_id"], base_time)
        else:  # new_device
            logs = generate_new_device_logs(
                user["user_id"], base_time, user["usual_devices"]
            )

        # N'ajoute le scénario que s'il ne dépasse pas le quota
        if len(attack_logs) + len(logs) <= n_attack_logs:
            attack_logs.extend(logs)

    return attack_logs


# ---------------------------------------------------------------------------
# Fonction principale
# ---------------------------------------------------------------------------

def generate_logs():
    """Orchestration complète de la génération de logs synthétiques."""

    start_time = time.time()

    # -- Configuration -------------------------------------------------------
    n_users      = USER_CONFIG_N = 100
    total_logs   = LOG_CONFIG["total_logs"]
    attack_ratio = LOG_CONFIG["attack_ratio"]
    days_back    = LOG_CONFIG["days_back"]

    n_attack_logs = int(total_logs * attack_ratio)          # 1000
    n_normal_logs = total_logs - n_attack_logs              # 4000

    print_separator("🚀 GÉNÉRATEUR DE LOGS SYNTHÉTIQUES - ZERO TRUST POLICY AGENT")
    print(f"\nConfiguration :")
    print(f"  - Utilisateurs      : {n_users}")
    print(f"  - Logs totaux       : {total_logs}")
    print(f"  - Période           : {days_back} jours")
    print(f"  - Logs normaux      : {n_normal_logs}  ({(1 - attack_ratio) * 100:.0f}%)")
    print(f"  - Logs d'attaque    : {n_attack_logs}  ({attack_ratio * 100:.0f}%)")

    # -- Étape 1 : profils utilisateurs --------------------------------------
    print_separator("ÉTAPE 1 : CRÉATION DES PROFILS UTILISATEURS")

    users      = generate_user_profiles(n_users)
    users_file = os.path.join(DATA_DIR, "users_profiles.json")
    save_user_profiles(users, users_file)

    # -- Étape 2 : génération des logs ---------------------------------------
    print_separator("ÉTAPE 2 : GÉNÉRATION DES LOGS")

    end_date   = datetime.now()
    start_date = end_date - timedelta(days=days_back)
    all_logs   = []

    # Logs normaux : distribués équitablement entre les utilisateurs
    print("Génération des logs normaux...")
    logs_per_user = n_normal_logs // n_users
    remainder     = n_normal_logs % n_users

    for i, user in enumerate(users):
        extra = 1 if i < remainder else 0
        logs  = generate_normal_logs(user, start_date, end_date, logs_per_user + extra)
        all_logs.extend(logs)

    # Logs d'attaque : quota strict
    print("Génération des logs d'attaque...")
    attack_logs = generate_attack_logs(users, n_attack_logs, start_date, days_back)
    all_logs.extend(attack_logs)

    # -- Étape 3 : tri et sauvegarde -----------------------------------------
    print_separator("ÉTAPE 3 : SAUVEGARDE DES FICHIERS")

    df = pd.DataFrame(all_logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    csv_file  = os.path.join(DATA_DIR, "logs_synthetiques.csv")
    json_file = os.path.join(DATA_DIR, "logs_synthetiques.json")

    save_csv(df, csv_file)
    save_json(df.to_dict(orient="records"), json_file)

    # -- Rapport final -------------------------------------------------------
    elapsed = time.time() - start_time
    total   = len(df)
    n_norm  = int((~df["is_attack"]).sum())
    n_att   = int(df["is_attack"].sum())

    print_separator("✅ GÉNÉRATION TERMINÉE AVEC SUCCÈS !")
    print(f"\n📊 Statistiques :")
    print(f"  - Total logs        : {total}")
    print(f"  - Logs normaux      : {n_norm}  ({n_norm / total * 100:.1f}%)")
    print(f"  - Logs d'attaque    : {n_att}   ({n_att / total * 100:.1f}%)")
    print(f"\n  Détail par type d'attaque :")

    for atype in df[df["is_attack"]]["attack_type"].dropna().unique():
        count = int((df["attack_type"] == atype).sum())
        pct   = count / n_att * 100
        print(f"      - {atype:<20} : {count:>4}  ({pct:.1f}%)")

    print(f"\n  ⏱  Durée d'exécution : {elapsed:.2f}s")
    print(f"  📁 Fichiers dans     : {DATA_DIR}\n")

    return df


# ---------------------------------------------------------------------------
# Guard : évite les exécutions multiples dues aux imports
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    generate_logs()
    