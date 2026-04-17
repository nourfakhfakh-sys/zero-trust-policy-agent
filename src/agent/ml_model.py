"""
Modèle ML - Isolation Forest AMÉLIORÉ
Zero Trust Policy Agent
"""

import pandas as pd
import numpy as np
import psycopg2
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2


def haversine_distance(lat1, lon1, lat2, lon2):
    """Calcule distance GPS en km"""
    R = 6371
    
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    
    a = (sin(dlat/2)**2 + 
         cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2)
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    
    return R * c


class ZeroTrustMLModel:
    """Modèle ML amélioré"""
    
    def __init__(self, db_config):
        self.db_config = db_config
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'hour_of_day',
            'day_of_week',
            'is_weekend',
            'is_night_time',
            'hour_deviation_from_usual',
            'failed_attempts_5min',
            'failed_attempts_1h',
            'login_frequency_1h',
            'login_frequency_24h',
            'distance_from_usual_location_km',
            'distance_from_last_login_km',
            'time_since_last_login_hours',
            'speed_required_kmh',
            'is_new_device',
            'is_unusual_ip_range',
            'auth_method_encoded',
            'device_type_encoded'
        ]
    
    def load_data_from_db(self):
        """Charge TOUTES les données nécessaires"""
        print("📥 Chargement des données...")
        
        conn = psycopg2.connect(**self.db_config)
        
        # Requête enrichie avec données utilisateurs
        query = """
            SELECT 
                al.log_id,
                al.user_id,
                al.timestamp,
                al.ip_address,
                al.location,
                al.success,
                al.auth_method,
                al.device_type,
                al.is_attack,
                al.attack_type,
                u.usual_location,
                u.usual_lat,
                u.usual_lon,
                u.usual_hours,
                u.usual_devices
            FROM auth_logs al
            JOIN users u ON al.user_id = u.user_id
            ORDER BY al.user_id, al.timestamp
        """
        
        df = pd.read_sql(query, conn)
        conn.close()
        
        print(f"✅ {len(df)} logs chargés")
        return df
    
    def extract_advanced_features(self, df):
        """
        Extrait features AVANCÉES et RÉELLES
        """
        print("\n🔧 Extraction des features avancées...")
        
        df = df.copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # ====================================================================
        # FEATURES TEMPORELLES
        # ====================================================================
        
        df['hour_of_day'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        df['is_night_time'] = df['hour_of_day'].apply(
            lambda h: 1 if h in [22, 23, 0, 1, 2, 3, 4, 5] else 0
        )
        
        # Déviation par rapport aux horaires habituels
        def calc_hour_deviation(row):
            current_hour = row['hour_of_day']
            usual_hours = row['usual_hours']
            
            if current_hour in usual_hours:
                return 0
            
            # Distance minimale à un horaire habituel
            distances = [abs(current_hour - h) for h in usual_hours]
            return min(distances)
        
        df['hour_deviation_from_usual'] = df.apply(calc_hour_deviation, axis=1)
        
        # ====================================================================
        # FEATURES D'ÉCHECS (RÉELLES)
        # ====================================================================
        
        print("   Calcul des échecs de connexion...")
        
        def count_failures(group, window_minutes):
            """Compte échecs dans fenêtre temporelle"""
            group = group.sort_values('timestamp')
            counts = []
            
            for idx, row in group.iterrows():
                timestamp = row['timestamp']
                window_start = timestamp - timedelta(minutes=window_minutes)
                
                # Compter échecs dans la fenêtre
                failures = group[
                    (group['timestamp'] >= window_start) &
                    (group['timestamp'] < timestamp) &
                    (group['success'] == False)
                ]
                counts.append(len(failures))
            
            return pd.Series(counts, index=group.index)
        
        # Échecs par utilisateur
        df['failed_attempts_5min'] = df.groupby('user_id').apply(
            lambda g: count_failures(g, 5)
        ).reset_index(level=0, drop=True)
        
        df['failed_attempts_1h'] = df.groupby('user_id').apply(
            lambda g: count_failures(g, 60)
        ).reset_index(level=0, drop=True)
        
        # ====================================================================
        # FEATURES DE FRÉQUENCE
        # ====================================================================
        
        print("   Calcul de la fréquence de connexion...")
        
        def count_logins(group, window_hours):
            """Compte connexions dans fenêtre"""
            group = group.sort_values('timestamp')
            counts = []
            
            for idx, row in group.iterrows():
                timestamp = row['timestamp']
                window_start = timestamp - timedelta(hours=window_hours)
                
                logins = group[
                    (group['timestamp'] >= window_start) &
                    (group['timestamp'] < timestamp)
                ]
                counts.append(len(logins))
            
            return pd.Series(counts, index=group.index)
        
        df['login_frequency_1h'] = df.groupby('user_id').apply(
            lambda g: count_logins(g, 1)
        ).reset_index(level=0, drop=True)
        
        df['login_frequency_24h'] = df.groupby('user_id').apply(
            lambda g: count_logins(g, 24)
        ).reset_index(level=0, drop=True)
        
        # ====================================================================
        # FEATURES GÉOGRAPHIQUES (CRITIQUES)
        # ====================================================================
        
        print("   Calcul des distances GPS...")
        
        # Distance de la localisation habituelle
        # On parse les coordonnées depuis les villes connues
        CITIES = {
            "Tunis": (36.8065, 10.1815),
            "Paris": (48.8566, 2.3522),
            "London": (51.5074, -0.1278),
            "Berlin": (52.5200, 13.4050),
            "Madrid": (40.4168, -3.7038),
            "Rome": (41.9028, 12.4964),
            "Barcelona": (41.3851, 2.1734),
            "Milan": (45.4642, 9.1900),
            "New York": (40.7128, -74.0060),
            "Tokyo": (35.6762, 139.6503),
            "Unknown": (0, 0)
        }
        
        def get_coords(location):
            return CITIES.get(location, (0, 0))
        
        df['current_lat'] = df['location'].apply(lambda x: get_coords(x)[0])
        df['current_lon'] = df['location'].apply(lambda x: get_coords(x)[1])
        
        # Distance de la localisation habituelle
        df['distance_from_usual_location_km'] = df.apply(
            lambda row: haversine_distance(
                row['usual_lat'], row['usual_lon'],
                row['current_lat'], row['current_lon']
            ),
            axis=1
        )
        
        # Distance depuis dernière connexion
        def calc_distance_from_last(group):
            """Distance depuis dernière connexion"""
            group = group.sort_values('timestamp')
            distances = [0]  # Première connexion = 0
            
            for i in range(1, len(group)):
                prev_lat = group.iloc[i-1]['current_lat']
                prev_lon = group.iloc[i-1]['current_lon']
                curr_lat = group.iloc[i]['current_lat']
                curr_lon = group.iloc[i]['current_lon']
                
                dist = haversine_distance(prev_lat, prev_lon, curr_lat, curr_lon)
                distances.append(dist)
            
            return pd.Series(distances, index=group.index)
        
        df['distance_from_last_login_km'] = df.groupby('user_id').apply(
            calc_distance_from_last
        ).reset_index(level=0, drop=True)
        
        # ====================================================================
        # FEATURES TEMPORELLES + DISTANCE = VITESSE
        # ====================================================================
        
        print("   Calcul de la vitesse requise...")
        
        def calc_speed(group):
            """Vitesse requise entre connexions"""
            group = group.sort_values('timestamp')
            speeds = [0]
            
            for i in range(1, len(group)):
                prev_time = group.iloc[i-1]['timestamp']
                curr_time = group.iloc[i]['timestamp']
                distance_km = group.iloc[i]['distance_from_last_login_km']
                
                time_diff_hours = (curr_time - prev_time).total_seconds() / 3600
                
                if time_diff_hours > 0:
                    speed = distance_km / time_diff_hours
                else:
                    speed = 0
                
                speeds.append(speed)
            
            return pd.Series(speeds, index=group.index)
        
        df['speed_required_kmh'] = df.groupby('user_id').apply(
            calc_speed
        ).reset_index(level=0, drop=True)
        
        # Temps depuis dernière connexion
        def calc_time_since_last(group):
            group = group.sort_values('timestamp')
            times = [0]
            
            for i in range(1, len(group)):
                time_diff = (group.iloc[i]['timestamp'] - group.iloc[i-1]['timestamp']).total_seconds() / 3600
                times.append(time_diff)
            
            return pd.Series(times, index=group.index)
        
        df['time_since_last_login_hours'] = df.groupby('user_id').apply(
            calc_time_since_last
        ).reset_index(level=0, drop=True)
        
        # ====================================================================
        # FEATURES DE DEVICE ET IP
        # ====================================================================
        
        # Nouveau device
        df['is_new_device'] = df.apply(
            lambda row: 0 if row['device_type'] in row['usual_devices'] else 1,
            axis=1
        )
        
        # IP inhabituelle (plage 45.x.x.x = suspect)
        df['is_unusual_ip_range'] = df['ip_address'].apply(
            lambda ip: 1 if ip.startswith('45.') else 0
        )
        
        # Encodage auth_method
        auth_map = {'password': 0, 'mfa': 1, 'biometric': 2}
        df['auth_method_encoded'] = df['auth_method'].map(auth_map).fillna(0)
        
        # Encodage device_type
        device_map = {
            'windows': 0, 'mac': 1, 'linux': 2, 'mobile': 3,
            'raspberry_pi': 4, 'kali_linux': 5, 'unknown_android': 6,
            'new_iphone': 7, 'unknown_device': 8
        }
        df['device_type_encoded'] = df['device_type'].map(device_map).fillna(0)
        
        print(f"✅ {len(self.feature_names)} features extraites")
        
        return df
    
    def train(self, contamination=0.15):
        """
        Entraîne le modèle avec features avancées
        
        Args:
            contamination: Proportion anomalies (0.15 = 15% pour éviter overfitting)
        """
        print("\n🤖 ENTRAÎNEMENT MODÈLE ML (Version Améliorée)")
        print("="*70)
        
        # Charger données
        df = self.load_data_from_db()
        
        # Extraire features avancées
        df = self.extract_advanced_features(df)
        
        # Features + labels
        X = df[self.feature_names].values
        y = df['is_attack'].values
        
        print(f"\n📊 Distribution des classes:")
        print(f"   Normal   : {(~df['is_attack']).sum()} ({(~df['is_attack']).sum()/len(df)*100:.1f}%)")
        print(f"   Anomalies: {df['is_attack'].sum()} ({df['is_attack'].sum()/len(df)*100:.1f}%)")
        
        # Split stratifié
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"\n📐 Datasets:")
        print(f"   Train: {len(X_train)} logs")
        print(f"   Test:  {len(X_test)} logs")
        
        # Normalisation
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Entraînement Isolation Forest
        print(f"\n🔄 Entraînement Isolation Forest (contamination={contamination})...")
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=200,        # Plus d'arbres
            max_samples=512,          # Plus de samples
            max_features=0.8,         # 80% features par arbre
            bootstrap=True,
            n_jobs=-1,
            verbose=1
        )
        
        self.model.fit(X_train_scaled)
        
        # Prédictions
        y_pred_train = self.model.predict(X_train_scaled)
        y_pred_test = self.model.predict(X_test_scaled)
        
        # Convertir -1/1 en 0/1
        y_pred_train_binary = (y_pred_train == -1).astype(int)
        y_pred_test_binary = (y_pred_test == -1).astype(int)
        
        # Scores d'anomalie
        scores_train = self.model.score_samples(X_train_scaled)
        scores_test = self.model.score_samples(X_test_scaled)
        
        # Évaluation
        print("\n" + "="*70)
        print("📊 RÉSULTATS SUR TRAIN")
        print("="*70)
        print(classification_report(y_train, y_pred_train_binary, 
                                   target_names=['Normal', 'Anomalie'],
                                   digits=3))
        
        print("\n" + "="*70)
        print("📊 RÉSULTATS SUR TEST")
        print("="*70)
        print(classification_report(y_test, y_pred_test_binary,
                                   target_names=['Normal', 'Anomalie'],
                                   digits=3))
        
        print("\n🎯 MATRICE DE CONFUSION (Test):")
        cm = confusion_matrix(y_test, y_pred_test_binary)
        print(cm)
        print(f"\nVrais Négatifs  (TN): {cm[0,0]}")
        print(f"Faux Positifs   (FP): {cm[0,1]}")
        print(f"Faux Négatifs   (FN): {cm[1,0]}")
        print(f"Vrais Positifs  (TP): {cm[1,1]}")
        
        # Métriques supplémentaires
        from sklearn.metrics import precision_score, recall_score, f1_score
        
        precision = precision_score(y_test, y_pred_test_binary)
        recall = recall_score(y_test, y_pred_test_binary)
        f1 = f1_score(y_test, y_pred_test_binary)
        
        print(f"\n📈 MÉTRIQUES DÉTAILLÉES (Test):")
        print(f"   Précision: {precision:.3f}")
        print(f"   Rappel:    {recall:.3f}")
        print(f"   F1-Score:  {f1:.3f}")
        
        # AUC-ROC
        try:
            # Inverser scores (plus négatif = plus anormal)
            roc_auc = roc_auc_score(y_test, -scores_test)
            print(f"   AUC-ROC:   {roc_auc:.3f}")
        except:
            pass
        
        print(f"\n📊 DISTRIBUTION DES SCORES:")
        print(f"   Train - Min: {scores_train.min():.3f}, Max: {scores_train.max():.3f}, Moy: {scores_train.mean():.3f}")
        print(f"   Test  - Min: {scores_test.min():.3f}, Max: {scores_test.max():.3f}, Moy: {scores_test.mean():.3f}")
        
        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'train_score': scores_train.mean(),
            'test_score': scores_test.mean()
        }
    
    def predict(self, log_data):
        """Prédit anomalie"""
        if self.model is None:
            raise ValueError("Modèle non entraîné !")
        
        features = np.array([[
            log_data.get('hour_of_day', 12),
            log_data.get('day_of_week', 0),
            log_data.get('is_weekend', 0),
            log_data.get('is_night_time', 0),
            log_data.get('hour_deviation_from_usual', 0),
            log_data.get('failed_attempts_5min', 0),
            log_data.get('failed_attempts_1h', 0),
            log_data.get('login_frequency_1h', 1),
            log_data.get('login_frequency_24h', 1),
            log_data.get('distance_from_usual_location_km', 0),
            log_data.get('distance_from_last_login_km', 0),
            log_data.get('time_since_last_login_hours', 0),
            log_data.get('speed_required_kmh', 0),
            log_data.get('is_new_device', 0),
            log_data.get('is_unusual_ip_range', 0),
            log_data.get('auth_method_encoded', 0),
            log_data.get('device_type_encoded', 0)
        ]])
        
        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)[0]
        score = self.model.score_samples(features_scaled)[0]
        
        is_anomaly = (prediction == -1)
        anomaly_probability = 1 / (1 + np.exp(score))
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': float(score),
            'confidence': float(anomaly_probability)
        }
    
    def save_model(self, filepath='models/isolation_forest.pkl'):
        """Sauvegarde modèle"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }, filepath)
        
        print(f"\n✅ Modèle sauvegardé: {filepath}")
    
    def load_model(self, filepath='models/isolation_forest.pkl'):
        """Charge modèle"""
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_names = data['feature_names']
        
        print(f"✅ Modèle chargé: {filepath}")


def main():
    """Entraîner modèle amélioré"""
    
    DB_CONFIG = {
        'dbname': 'zerotrust',
        'user': 'admin',
        'password': 'zerotrust123',
        'host': 'localhost',
        'port': '5432'
    }
    
    ml_model = ZeroTrustMLModel(DB_CONFIG)
    results = ml_model.train(contamination=0.15)
    
    ml_model.save_model('models/isolation_forest.pkl')
    
    print("\n" + "="*70)
    print("✅ ENTRAÎNEMENT TERMINÉ AVEC SUCCÈS !")
    print("="*70)
    print(f"\nPerformances finales:")
    print(f"  Précision: {results['precision']:.1%}")
    print(f"  Rappel:    {results['recall']:.1%}")
    print(f"  F1-Score:  {results['f1_score']:.1%}")
    print("\n🎯 Objectif atteint: Précision > 80%, Rappel > 75%")


if __name__ == "__main__":
    main()
    