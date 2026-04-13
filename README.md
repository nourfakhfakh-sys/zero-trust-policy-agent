# Zero Trust Policy Agent

Agent intelligent de détection d'anomalies et de politiques de sécurité adaptatives.

## 📋 Description

Système automatisé qui analyse les logs d'authentification en temps réel, détecte les comportements suspects et applique des politiques de sécurité adaptatives (Allow, MFA, Block).

## 🎯 Anomalies Détectées

- Brute-force (tentatives multiples échouées)
- Impossible travel (géolocalisation incohérente)
- Horaires anormaux (hors plages habituelles)
- Nouveaux devices/IP (première connexion)

## 🏗️ Technologies

- **Backend:** Python 3.11+, FastAPI
- **ML:** Scikit-learn (Isolation Forest)
- **Database:** PostgreSQL
- **Dashboard:** Streamlit
- **Déploiement:** Docker Compose

## 📂 Structure