"""
Règles de détection d'anomalies - Zero Trust Policy Agent
"""

from datetime import datetime, timedelta
import psycopg2
from typing import Dict, List, Optional


class DetectionRules:
    """Moteur de règles de détection"""
    
    def __init__(self, db_config):
        self.db_config = db_config
    
    def get_connection(self):
        """Connexion DB"""
        return psycopg2.connect(**self.db_config)
    
    # ========================================================================
    # RÈGLE 1 : BRUTE-FORCE
    # ========================================================================
    
    def detect_bruteforce(self, user_id: str, timestamp: datetime, 
                         threshold: int = 5) -> Dict:
        """
        Détecte tentatives brute-force (5+ échecs en 5 min)
        
        Args:
            user_id: ID utilisateur
            timestamp: Moment de la tentative
            threshold: Nombre d'échecs max (défaut: 5)
            
        Returns:
            dict: {
                'is_anomaly': bool,
                'severity': str,
                'details': dict
            }
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Compter échecs dans les 5 dernières minutes
        cursor.execute("""
            SELECT COUNT(*) 
            FROM auth_logs
            WHERE user_id = %s
              AND success = FALSE
              AND timestamp BETWEEN %s AND %s
        """, (
            user_id,
            timestamp - timedelta(minutes=5),
            timestamp
        ))
        
        failed_count = cursor.fetchone()[0]
        conn.close()
        
        is_anomaly = failed_count >= threshold
        
        return {
            'is_anomaly': is_anomaly,
            'severity': 'high' if failed_count >= 10 else 'medium',
            'details': {
                'rule': 'bruteforce',
                'failed_attempts': failed_count,
                'threshold': threshold,
                'time_window': '5 minutes'
            }
        }
    
    # ========================================================================
    # RÈGLE 2 : IMPOSSIBLE TRAVEL
    # ========================================================================
    
    def detect_impossible_travel(self, user_id: str, current_location: tuple,
                                current_timestamp: datetime) -> Dict:
        """
        Détecte voyage impossible (distance/temps physiquement irréalisable)
        
        Args:
            user_id: ID utilisateur
            current_location: (latitude, longitude) actuelle
            current_timestamp: Moment actuel
            
        Returns:
            dict: Résultat de détection
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Dernière connexion de cet utilisateur
        cursor.execute("""
            SELECT al.timestamp, al.location, u.usual_lat, u.usual_lon
            FROM auth_logs al
            JOIN users u ON al.user_id = u.user_id
            WHERE al.user_id = %s
              AND al.timestamp < %s
            ORDER BY al.timestamp DESC
            LIMIT 1
        """, (user_id, current_timestamp))
        
        last_login = cursor.fetchone()
        conn.close()
        
        if not last_login:
            return {'is_anomaly': False, 'severity': 'none', 'details': {}}
        
        last_time, last_loc, last_lat, last_lon = last_login
        
        # Calculer distance
        distance_km = self._haversine_distance(
            (last_lat, last_lon),
            current_location
        )
        
        # Calculer temps écoulé
        time_diff = (current_timestamp - last_time).total_seconds() / 3600  # heures
        
        # Vitesse moyenne nécessaire (km/h)
        speed_required = distance_km / time_diff if time_diff > 0 else 0
        
        # Impossible si vitesse > 900 km/h (avion de ligne ~800 km/h)
        is_anomaly = speed_required > 900
        
        return {
            'is_anomaly': is_anomaly,
            'severity': 'critical' if is_anomaly else 'low',
            'details': {
                'rule': 'impossible_travel',
                'distance_km': round(distance_km, 2),
                'time_hours': round(time_diff, 2),
                'speed_required_kmh': round(speed_required, 2),
                'last_location': last_loc,
                'current_location': 'Current'
            }
        }
    
    def _haversine_distance(self, coord1: tuple, coord2: tuple) -> float:
        """Calcul distance GPS (Haversine)"""
        from math import radians, sin, cos, sqrt, atan2
        
        lat1, lon1 = coord1
        lat2, lon2 = coord2
        
        R = 6371  # Rayon Terre en km
        
        dlat = radians(lat2 - lat1)
        dlon = radians(lon2 - lon1)
        
        a = (sin(dlat/2)**2 + 
             cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2)
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        return R * c
    
    # ========================================================================
    # RÈGLE 3 : HORAIRES ANORMAUX
    # ========================================================================
    
    def detect_unusual_hour(self, user_id: str, timestamp: datetime) -> Dict:
        """
        Détecte connexion hors horaires habituels
        
        Args:
            user_id: ID utilisateur
            timestamp: Moment de connexion
            
        Returns:
            dict: Résultat détection
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Récupérer horaires habituels
        cursor.execute("""
            SELECT usual_hours
            FROM users
            WHERE user_id = %s
        """, (user_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return {'is_anomaly': False, 'severity': 'none', 'details': {}}
        
        usual_hours = result[0]  # JSONB devient liste Python
        current_hour = timestamp.hour
        
        is_anomaly = current_hour not in usual_hours
        
        # Nuit profonde (22h-6h) = critique
        is_night = current_hour in [22, 23, 0, 1, 2, 3, 4, 5]
        
        return {
            'is_anomaly': is_anomaly,
            'severity': 'high' if is_night else 'medium',
            'details': {
                'rule': 'unusual_hour',
                'current_hour': current_hour,
                'usual_hours': usual_hours,
                'is_night_time': is_night
            }
        }
    
    # ========================================================================
    # RÈGLE 4 : NOUVEAU DEVICE
    # ========================================================================
    
    def detect_new_device(self, user_id: str, device_type: str) -> Dict:
        """
        Détecte connexion depuis device inconnu
        
        Args:
            user_id: ID utilisateur
            device_type: Type de device actuel
            
        Returns:
            dict: Résultat détection
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Récupérer devices habituels
        cursor.execute("""
            SELECT usual_devices
            FROM users
            WHERE user_id = %s
        """, (user_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return {'is_anomaly': False, 'severity': 'none', 'details': {}}
        
        usual_devices = result[0]  # JSONB
        is_anomaly = device_type not in usual_devices
        
        # Devices suspects
        suspicious = ['raspberry_pi', 'kali_linux', 'unknown_device']
        is_suspicious = device_type in suspicious
        
        return {
            'is_anomaly': is_anomaly,
            'severity': 'high' if is_suspicious else 'medium',
            'details': {
                'rule': 'new_device',
                'current_device': device_type,
                'usual_devices': usual_devices,
                'is_suspicious_device': is_suspicious
            }
        }
    
    # ========================================================================
    # ANALYSE COMPLÈTE
    # ========================================================================
    
    def analyze_login(self, log_data: Dict) -> Dict:
        """
        Analyse complète d'une tentative de connexion
        
        Args:
            log_data: {
                'user_id': str,
                'timestamp': datetime,
                'location': tuple (lat, lon),
                'device_type': str,
                ...
            }
            
        Returns:
            dict: {
                'anomalies': list,
                'risk_score': float,
                'decision': str  # ALLOW, MFA, BLOCK
            }
        """
        anomalies = []
        
        # Tester toutes les règles
        bf = self.detect_bruteforce(
            log_data['user_id'], 
            log_data['timestamp']
        )
        if bf['is_anomaly']:
            anomalies.append(bf)
        
        it = self.detect_impossible_travel(
            log_data['user_id'],
            log_data['location'],
            log_data['timestamp']
        )
        if it['is_anomaly']:
            anomalies.append(it)
        
        uh = self.detect_unusual_hour(
            log_data['user_id'],
            log_data['timestamp']
        )
        if uh['is_anomaly']:
            anomalies.append(uh)
        
        nd = self.detect_new_device(
            log_data['user_id'],
            log_data['device_type']
        )
        if nd['is_anomaly']:
            anomalies.append(nd)
        
        # Calculer risque
        risk_score = self._calculate_risk_score(anomalies)
        
        # Décision
        if risk_score >= 0.8:
            decision = 'BLOCK'
        elif risk_score >= 0.5:
            decision = 'MFA'
        else:
            decision = 'ALLOW'
        
        return {
            'anomalies': anomalies,
            'risk_score': risk_score,
            'decision': decision
        }
    
    def _calculate_risk_score(self, anomalies: List[Dict]) -> float:
        """Calcul score de risque"""
        if not anomalies:
            return 0.0
        
        severity_weights = {
            'critical': 1.0,
            'high': 0.7,
            'medium': 0.4,
            'low': 0.2
        }
        
        total = sum(severity_weights.get(a['severity'], 0) for a in anomalies)
        return min(total / len(anomalies), 1.0)
    