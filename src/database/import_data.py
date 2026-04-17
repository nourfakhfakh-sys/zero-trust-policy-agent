"""
Script d'import des logs synthétiques dans PostgreSQL
Zero Trust Policy Agent
"""

import psycopg2
import json
import pandas as pd
import sys
import os
from datetime import datetime

# Configuration de la connexion PostgreSQL
DB_CONFIG = {
    'dbname': 'zerotrust',
    'user': 'admin',           
    'password': 'zerotrust123',
    'host': 'localhost',
    'port': '5432'
}

# Chemins des fichiers
# Chemins des fichiers
DATA_DIR = r'C:\Users\lenovo\OneDrive\Bureau\PFA 2026\zero-trust-policy-agent\data'
USERS_FILE = DATA_DIR + r'\users_profiles.json'
LOGS_FILE = DATA_DIR + r'\logs_synthetiques.csv'

def connect_db():
    """Connexion à PostgreSQL"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        print("✅ Connexion à PostgreSQL réussie")
        return conn
    except Exception as e:
        print(f"❌ Erreur de connexion : {e}")
        sys.exit(1)


def import_users(conn):
    """Importe les profils utilisateurs"""
    print("\n📥 Import des utilisateurs...")
    
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        users = json.load(f)
    
    cursor = conn.cursor()
    
    for user in users:
        cursor.execute("""
            INSERT INTO users (
                user_id, email, name, department,
                usual_location, usual_lat, usual_lon,
                usual_hours, usual_devices, risk_score, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                email = EXCLUDED.email,
                updated_at = NOW()
        """, (
            user['user_id'],
            user['email'],
            user['name'],
            user['department'],
            user['usual_location'],
            user['usual_lat'],
            user['usual_lon'],
            json.dumps(user['usual_hours']),
            json.dumps(user['usual_devices']),
            user['risk_score'],
            user['created_at']
        ))
    
    conn.commit()
    print(f"✅ {len(users)} utilisateurs importés")


def import_logs(conn):
    """Importe les logs d'authentification"""
    print("\n📥 Import des logs...")
    
    df = pd.read_csv(LOGS_FILE)
    
    cursor = conn.cursor()
    
    for _, row in df.iterrows():
        attack_type = row['attack_type'] if pd.notna(row['attack_type']) else None
        
        cursor.execute("""
            INSERT INTO auth_logs (
                user_id, timestamp, ip_address, location,
                success, auth_method, device_type,
                is_attack, attack_type
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            row['user_id'],
            row['timestamp'],
            row['ip_address'],
            row['location'],
            row['success'],
            row['auth_method'],
            row['device_type'],
            row['is_attack'],
            attack_type
        ))
    
    conn.commit()
    print(f"✅ {len(df)} logs importés")


def verify_import(conn):
    """Vérifie l'import"""
    print("\n🔍 Vérification de l'import...")
    
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM users")
    nb_users = cursor.fetchone()[0]
    print(f"   Utilisateurs : {nb_users}")
    
    cursor.execute("SELECT COUNT(*) FROM auth_logs")
    nb_logs = cursor.fetchone()[0]
    print(f"   Logs totaux  : {nb_logs}")
    
    cursor.execute("SELECT COUNT(*) FROM auth_logs WHERE is_attack = TRUE")
    nb_attacks = cursor.fetchone()[0]
    print(f"   Attaques     : {nb_attacks} ({nb_attacks/nb_logs*100:.1f}%)")
    
    cursor.execute("""
        SELECT attack_type, COUNT(*) 
        FROM auth_logs 
        WHERE is_attack = TRUE 
        GROUP BY attack_type
    """)
    
    print(f"\n   Détail des attaques :")
    for attack_type, count in cursor.fetchall():
        print(f"      - {attack_type}: {count}")


def main():
    print("="*70)
    print("🚀 IMPORT DES DONNÉES DANS POSTGRESQL")
    print("="*70)
    
    conn = connect_db()
    
    try:
        import_users(conn)
        import_logs(conn)
        verify_import(conn)
        
        print("\n" + "="*70)
        print("✅ IMPORT TERMINÉ AVEC SUCCÈS !")
        print("="*70)
        
    except Exception as e:
        print(f"\n❌ Erreur pendant l'import : {e}")
        conn.rollback()
    
    finally:
        conn.close()


if __name__ == "__main__":
    main()