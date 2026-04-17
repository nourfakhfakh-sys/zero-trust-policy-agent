"""
API REST - Zero Trust Policy Agent
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List
import sys
import os

# Ajouter src/agent au path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'agent'))

from hybrid_agent import HybridZeroTrustAgent

# Configuration
DB_CONFIG = {
    'dbname': 'zerotrust',
    'user': 'admin',
    'password': 'zerotrust123',
    'host': 'localhost',
    'port': '5432'
}

# Initialiser FastAPI
app = FastAPI(
    title="Zero Trust Policy Agent API",
    description="API pour l'analyse de logs d'authentification",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Agent hybride
agent = HybridZeroTrustAgent(DB_CONFIG)


# ============================================================================
# MODÈLES PYDANTIC
# ============================================================================

class LoginRequest(BaseModel):
    """Requête d'authentification"""
    user_id: str
    username: Optional[str] = None
    ip_address: str
    latitude: float
    longitude: float
    device_type: str
    auth_method: str = "password"
    timestamp: Optional[str] = None
    
    class Config:
        schema_extra = {
            "example": {
                "user_id": "user_001",
                "username": "alice@example.com",
                "ip_address": "192.168.1.100",
                "latitude": 36.8065,
                "longitude": 10.1815,
                "device_type": "windows",
                "auth_method": "password"
            }
        }


class AuthResponse(BaseModel):
    """Réponse d'analyse"""
    decision: str  # ALLOW, MFA, BLOCK
    risk_score: float
    explanation: str
    triggered_rules: List[dict]
    ml_prediction: Optional[dict]
    timestamp: str


# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/")
def read_root():
    """Page d'accueil"""
    return {
        "message": "Zero Trust Policy Agent API",
        "version": "1.0.0",
        "endpoints": {
            "POST /auth/validate": "Analyser une tentative de connexion",
            "GET /stats": "Statistiques globales",
            "GET /health": "État de santé de l'API"
        }
    }


@app.post("/auth/validate", response_model=AuthResponse)
def validate_authentication(request: LoginRequest):
    """
    Analyse une tentative d'authentification
    
    - **user_id**: ID de l'utilisateur
    - **ip_address**: Adresse IP source
    - **latitude/longitude**: Coordonnées GPS
    - **device_type**: Type d'appareil
    - **auth_method**: Méthode d'authentification
    
    Returns:
        AuthResponse: Décision (ALLOW/MFA/BLOCK) + détails
    """
    
    try:
        # Préparer données pour l'agent
        log_data = {
            'user_id': request.user_id,
            'timestamp': datetime.fromisoformat(request.timestamp) if request.timestamp else datetime.now(),
            'ip_address': request.ip_address,
            'location': (request.latitude, request.longitude),
            'device_type': request.device_type,
            'auth_method': request.auth_method
        }
        
        # Analyser
        result = agent.analyze_login_attempt(log_data)
        
        return AuthResponse(**result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur d'analyse: {str(e)}")


@app.get("/stats")
def get_statistics():
    """Statistiques globales"""
    import psycopg2
    
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    
    # Total logs
    cursor.execute("SELECT COUNT(*) FROM auth_logs")
    total_logs = cursor.fetchone()[0]
    
    # Attaques
    cursor.execute("SELECT COUNT(*) FROM auth_logs WHERE is_attack = TRUE")
    total_attacks = cursor.fetchone()[0]
    
    # Par type
    cursor.execute("""
        SELECT attack_type, COUNT(*)
        FROM auth_logs
        WHERE is_attack = TRUE
        GROUP BY attack_type
    """)
    attacks_by_type = dict(cursor.fetchall())
    
    # Décisions (si table remplie)
    cursor.execute("SELECT decision, COUNT(*) FROM decisions GROUP BY decision")
    decisions = dict(cursor.fetchall())
    
    conn.close()
    
    return {
        "total_logs": total_logs,
        "total_attacks": total_attacks,
        "attack_rate": round(total_attacks / total_logs * 100, 2) if total_logs > 0 else 0,
        "attacks_by_type": attacks_by_type,
        "decisions": decisions
    }


@app.get("/health")
def health_check():
    """Vérification de santé"""
    import psycopg2
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.close()
        db_status = "OK"
    except:
        db_status = "ERROR"
    
    return {
        "status": "healthy" if db_status == "OK" else "unhealthy",
        "database": db_status,
        "ml_model": "loaded" if agent.ml_enabled else "not loaded",
        "timestamp": datetime.now().isoformat()
    }


# ============================================================================
# LANCEMENT
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)