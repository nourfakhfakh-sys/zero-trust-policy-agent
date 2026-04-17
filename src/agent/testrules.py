"""
Tests des règles de détection
"""

import psycopg2
from datetime import datetime
from rules import DetectionRules

# Configuration base de données
DB_CONFIG = {
    'dbname': 'zerotrust',
    'user': 'admin',
    'password': 'zerotrust123',
    'host': 'localhost',
    'port': '5432'
}

def test_bruteforce():
    """Test détection brute-force"""
    print("\n" + "="*60)
    print("🧪 TEST 1 : BRUTE-FORCE")
    print("="*60)
    
    rules = DetectionRules(DB_CONFIG)
    
    # Récupérer un utilisateur
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users LIMIT 1")
    user_id = cursor.fetchone()[0]
    conn.close()
    
    print(f"User: {user_id}")
    print(f"Timestamp: {datetime.now()}")
    
    result = rules.detect_bruteforce(user_id, datetime.now())
    
    print(f"Anomalie détectée: {result['is_anomaly']}")
    print(f"Sévérité: {result['severity']}")
    print(f"Détails: {result['details']}")
    
    if result['is_anomaly']:
        print("✅ Anomalie détectée !")
    else:
        print("❌ Échec de détection (normal car pas d'attaque)")

def test_impossible_travel():
    """Test détection impossible travel"""
    print("\n" + "="*60)
    print("🧪 TEST 2 : IMPOSSIBLE TRAVEL")
    print("="*60)
    
    rules = DetectionRules(DB_CONFIG)
    
    # Récupérer un utilisateur avec ses coordonnées
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT user_id, usual_lat, usual_lon
        FROM users
        WHERE usual_lat IS NOT NULL
        LIMIT 1
    """)
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        print("❌ Aucun utilisateur trouvé")
        return
    
    user_id, lat, lon = result
    current_location = (lat, lon)
    
    print(f"User: {user_id}")
    print(f"Location actuelle: {current_location}")
    
    # Tester avec un timestamp actuel
    result = rules.detect_impossible_travel(user_id, current_location, datetime.now())
    
    print(f"Anomalie détectée: {result['is_anomaly']}")
    print(f"Sévérité: {result['severity']}")
    print(f"Détails: {result['details']}")

def test_unusual_hour():
    """Test détection heure inhabituelle"""
    print("\n" + "="*60)
    print("🧪 TEST 3 : HEURE INHABITUELLE")
    print("="*60)
    
    rules = DetectionRules(DB_CONFIG)
    
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users LIMIT 1")
    user_id = cursor.fetchone()[0]
    conn.close()
    
    # Simuler une connexion à 3h du matin
    unusual_time = datetime.now().replace(hour=3, minute=0)
    
    print(f"User: {user_id}")
    print(f"Heure testée: {unusual_time.strftime('%H:%M')}")
    
    result = rules.detect_unusual_hour(user_id, unusual_time)
    
    print(f"Anomalie détectée: {result['is_anomaly']}")
    print(f"Sévérité: {result['severity']}")
    print(f"Détails: {result['details']}")

def test_new_device():
    """Test détection nouveau device"""
    print("\n" + "="*60)
    print("🧪 TEST 4 : NOUVEAU DEVICE")
    print("="*60)
    
    rules = DetectionRules(DB_CONFIG)
    
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users LIMIT 1")
    user_id = cursor.fetchone()[0]
    conn.close()
    
    print(f"User: {user_id}")
    print(f"Device testé: unknown_raspberry")
    
    result = rules.detect_new_device(user_id, "unknown_raspberry")
    
    print(f"Anomalie détectée: {result['is_anomaly']}")
    print(f"Sévérité: {result['severity']}")
    print(f"Détails: {result['details']}")

def main():
    print("🚀 LANCEMENT DES TESTS DE DÉTECTION")
    
    try:
        test_bruteforce()
        test_impossible_travel()
        test_unusual_hour()
        test_new_device()
        
        print("\n" + "="*60)
        print("✅ TOUS LES TESTS TERMINÉS")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ Erreur: {e}")

if __name__ == "__main__":
    main()
    