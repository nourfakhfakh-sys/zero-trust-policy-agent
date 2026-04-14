"""
Fonctions utilitaires pour le générateur de logs - Zero Trust Policy Agent
"""

import json
import os
import pandas as pd
from math import radians, sin, cos, sqrt, atan2
from datetime import datetime


def save_json(data, filepath):
    """Sauvegarde les données au format JSON"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    print(f"✅ JSON sauvegardé : {filepath}")


def save_csv(df, filepath):
    """Sauvegarde un DataFrame au format CSV"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    df.to_csv(filepath, index=False, encoding='utf-8')
    print(f"✅ CSV sauvegardé  : {filepath}")


def load_json(filepath):
    """Charge un fichier JSON"""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fichier introuvable : {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_csv(filepath):
    """Charge un fichier CSV en DataFrame"""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fichier introuvable : {filepath}")
    return pd.read_csv(filepath)


def calculate_distance(coord1, coord2):  # noqa: E302
    """
    Calcule la distance en km entre deux coordonnées GPS
    en utilisant la formule de Haversine.

    Args:
        coord1 (tuple): (latitude, longitude) du point 1
        coord2 (tuple): (latitude, longitude) du point 2

    Returns:
        float: distance en kilomètres
    """
    lat1, lon1 = coord1
    lat2, lon2 = coord2

    R = 6371  # Rayon terrestre en km

    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = (sin(dlat / 2) ** 2
         + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2)
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    return R * c


def print_separator(title=""):
    """Affiche un séparateur formaté"""
    line = "=" * 70
    if title:
        print(f"\n{line}")
        print(title)
        print(line)
    else:
        print(line)


def format_duration(seconds):
    """Formate une durée en secondes en chaîne lisible"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f}min"
    return f"{minutes / 60:.1f}h"
