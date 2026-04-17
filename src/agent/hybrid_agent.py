"""
Agent Hybride : Règles + Machine Learning
"""

from datetime import datetime
from rules import DetectionRules
from ml_model import ZeroTrustMLModel


class HybridZeroTrustAgent:
    """Agent Zero Trust hybride"""
    
    def __init__(self, db_config, ml_model_path='models/isolation_forest.pkl'):
        self.rules = DetectionRules(db_config)
        
        # Charger modèle ML
        self.ml_model = ZeroTrustMLModel(db_config)
        try:
            self.ml_model.load_model(ml_model_path)
            self.ml_enabled = True
        except:
            print("⚠️  Modèle ML non trouvé, règles seules activées")
            self.ml_enabled = False
    
    def analyze_login_attempt(self, log_data):
        """
        Analyse complète d'une tentative de connexion
        
        Args:
            log_data: dict {
                'user_id': str,
                'timestamp': datetime,
                'ip_address': str,
                'location': tuple (lat, lon),
                'device_type': str,
                'auth_method': str,
                ...
            }
            
        Returns:
            dict: {
                'decision': str (ALLOW/MFA/BLOCK),
                'risk_score': float,
                'triggered_rules': list,
                'ml_prediction': dict,
                'explanation': str
            }
        """
        
        # ÉTAPE 1 : Règles métier
        rule_analysis = self.rules.analyze_login(log_data)
        
        triggered_rules = []
        for anomaly in rule_analysis['anomalies']:
            triggered_rules.append({
                'rule': anomaly['details']['rule'],
                'severity': anomaly['severity'],
                'details': anomaly['details']
            })
        
        # ÉTAPE 2 : ML (si disponible)
        ml_prediction = None
        if self.ml_enabled:
            # Préparer features
            ml_features = {
                'hour_of_day': log_data['timestamp'].hour,
                'day_of_week': log_data['timestamp'].weekday(),
                'is_weekend': 1 if log_data['timestamp'].weekday() >= 5 else 0,
                'failed_attempts_5min': 0,  # Calculer depuis DB
                'login_frequency_1h': 1,
                'is_new_device_encoded': 1 if 'is_new_device' in [r['rule'] for r in triggered_rules] else 0,
                'auth_method_encoded': {'password': 0, 'mfa': 1, 'biometric': 2}.get(log_data.get('auth_method', 'password'), 0)
            }
            
            ml_prediction = self.ml_model.predict(ml_features)
        
        # ÉTAPE 3 : Décision finale (hybride)
        decision, risk_score, explanation = self._make_decision(
            rule_analysis,
            ml_prediction,
            triggered_rules
        )
        
        return {
            'decision': decision,
            'risk_score': risk_score,
            'triggered_rules': triggered_rules,
            'ml_prediction': ml_prediction,
            'explanation': explanation,
            'timestamp': datetime.now().isoformat()
        }
    
    def _make_decision(self, rule_analysis, ml_prediction, triggered_rules):
        """
        Décision finale hybride
        
        Priorité :
        1. Règles CRITIQUES → BLOCK immédiat
        2. ML score élevé → BLOCK
        3. Règles MEDIUM + ML → MFA
        4. Sinon → ALLOW
        """
        
        # Règles critiques
        critical_rules = [r for r in triggered_rules if r['severity'] == 'critical']
        if critical_rules:
            return 'BLOCK', 1.0, f"Règle critique déclenchée: {critical_rules[0]['rule']}"
        
        # Règles high severity
        high_rules = [r for r in triggered_rules if r['severity'] == 'high']
        
        # Combiner scores
        rule_score = rule_analysis['risk_score']
        ml_score = ml_prediction['confidence'] if ml_prediction else 0
        
        # Score hybride (70% règles, 30% ML)
        hybrid_score = (rule_score * 0.7) + (ml_score * 0.3)
        
        # Décision
        if hybrid_score >= 0.8 or len(high_rules) >= 2:
            return 'BLOCK', hybrid_score, f"Score de risque élevé: {hybrid_score:.2f}"
        
        elif hybrid_score >= 0.5 or len(high_rules) >= 1:
            return 'MFA', hybrid_score, f"Authentification supplémentaire requise (risque: {hybrid_score:.2f})"
        
        else:
            return 'ALLOW', hybrid_score, "Connexion normale"


# Test
if __name__ == "__main__":
    DB_CONFIG = {
        'dbname': 'zerotrust',
        'user': 'admin',
        'password': 'zerotrust123',
        'host': 'localhost',
        'port': '5432'
    }
    
    agent = HybridZeroTrustAgent(DB_CONFIG)
    
    # Test avec un log suspect
    test_log = {
        'user_id': 'user_001',
        'timestamp': datetime.now().replace(hour=3),  # 3h du matin
        'ip_address': '45.123.45.67',
        'location': (35.6762, 139.6503),  # Tokyo
        'device_type': 'kali_linux',
        'auth_method': 'password'
    }
    
    result = agent.analyze_login_attempt(test_log)
    
    print("\n🔍 RÉSULTAT ANALYSE:")
    print(f"Décision: {result['decision']}")
    print(f"Score: {result['risk_score']:.2f}")
    print(f"Explication: {result['explanation']}")
    print(f"Règles déclenchées: {len(result['triggered_rules'])}")