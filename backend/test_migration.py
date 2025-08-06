#!/usr/bin/env python3
"""
Script de test pour vérifier que la migration PostgreSQL fonctionne correctement
"""

import os
import sys
import logging
import traceback
from datetime import datetime

# Ajouter le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import test_connection, get_user_by_email, create_user, get_password_hash
from app.db.queries import create_meeting, get_meeting, update_meeting, get_meetings_by_user

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_database_connection():
    """Tester la connexion à la base de données"""
    logger.info("Test de connexion PostgreSQL...")
    try:
        result = test_connection()
        if result:
            logger.info("✅ Connexion PostgreSQL réussie")
            return True
        else:
            logger.error("❌ Échec de la connexion PostgreSQL")
            return False
    except Exception as e:
        logger.error(f"❌ Erreur de connexion: {e}")
        return False

def test_user_operations():
    """Tester les opérations sur les utilisateurs"""
    logger.info("Test des opérations utilisateurs...")
    
    try:
        # Test: Récupérer un utilisateur existant
        admin_user = get_user_by_email('admin@gilbert.com')
        if admin_user:
            logger.info(f"✅ Utilisateur admin trouvé: {admin_user['email']}")
        else:
            logger.warning("⚠️  Utilisateur admin non trouvé")
        
        # Test: Créer un utilisateur de test
        test_email = f"test-{datetime.now().strftime('%Y%m%d-%H%M%S')}@gilbert.com"
        user_data = {
            "email": test_email,
            "hashed_password": get_password_hash("testpassword"),
            "full_name": "Test User Migration"
        }
        
        new_user = create_user(user_data)
        if new_user:
            logger.info(f"✅ Nouvel utilisateur créé: {new_user['email']}")
            return new_user
        else:
            logger.error("❌ Échec de création d'utilisateur")
            return None
            
    except Exception as e:
        logger.error(f"❌ Erreur lors des tests utilisateurs: {e}")
        logger.error(traceback.format_exc())
        return None

def test_meeting_operations(user_id: str):
    """Tester les opérations sur les réunions"""
    logger.info("Test des opérations réunions...")
    
    try:
        # Test: Créer une réunion
        meeting_data = {
            "user_id": user_id,
            "title": f"Réunion test {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "file_url": "/test/audio.mp3",
            "transcript_status": "pending"
        }
        
        new_meeting = create_meeting(meeting_data)
        if new_meeting:
            logger.info(f"✅ Réunion créée: {new_meeting['title']}")
            meeting_id = new_meeting['id']
        else:
            logger.error("❌ Échec de création de réunion")
            return False
        
        # Test: Récupérer la réunion
        retrieved_meeting = get_meeting(meeting_id, user_id)
        if retrieved_meeting:
            logger.info(f"✅ Réunion récupérée: {retrieved_meeting['title']}")
        else:
            logger.error("❌ Échec de récupération de réunion")
            return False
        
        # Test: Mettre à jour la réunion
        update_data = {
            "transcript_status": "completed",
            "transcript_text": "Ceci est un test de transcription",
            "duration_seconds": 120,
            "speakers_count": 2
        }
        
        update_success = update_meeting(meeting_id, user_id, update_data)
        if update_success:
            logger.info("✅ Réunion mise à jour avec succès")
        else:
            logger.error("❌ Échec de mise à jour de réunion")
            return False
        
        # Test: Récupérer toutes les réunions de l'utilisateur
        user_meetings = get_meetings_by_user(user_id)
        if user_meetings and len(user_meetings) > 0:
            logger.info(f"✅ {len(user_meetings)} réunion(s) trouvée(s) pour l'utilisateur")
        else:
            logger.warning("⚠️  Aucune réunion trouvée pour l'utilisateur")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Erreur lors des tests réunions: {e}")
        logger.error(traceback.format_exc())
        return False

def test_authentication_flow():
    """Tester le flux d'authentification"""
    logger.info("Test du flux d'authentification...")
    
    try:
        # Test avec l'utilisateur admin par défaut
        admin_user = get_user_by_email('admin@gilbert.com')
        if not admin_user:
            logger.error("❌ Utilisateur admin non trouvé")
            return False
        
        # Vérifier que la structure contient les bons champs
        required_fields = ['id', 'email', 'password_hash', 'full_name']
        missing_fields = [field for field in required_fields if field not in admin_user]
        
        if missing_fields:
            logger.error(f"❌ Champs manquants dans l'utilisateur: {missing_fields}")
            return False
        
        logger.info("✅ Structure utilisateur valide")
        logger.info(f"   - ID: {admin_user['id']}")
        logger.info(f"   - Email: {admin_user['email']}")
        logger.info(f"   - Nom complet: {admin_user['full_name']}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du test d'authentification: {e}")
        logger.error(traceback.format_exc())
        return False

def main():
    """Fonction principale de test"""
    logger.info("=== DÉBUT DES TESTS DE MIGRATION ===")
    
    results = {
        'connection': False,
        'authentication': False,
        'users': False,
        'meetings': False
    }
    
    # Test 1: Connexion
    results['connection'] = test_database_connection()
    if not results['connection']:
        logger.error("Arrêt des tests: problème de connexion")
        return False
    
    # Test 2: Authentification
    results['authentication'] = test_authentication_flow()
    
    # Test 3: Opérations utilisateurs
    new_user = test_user_operations()
    if new_user:
        results['users'] = True
        user_id = new_user['id']
        
        # Test 4: Opérations réunions
        results['meetings'] = test_meeting_operations(user_id)
    
    # Résumé des résultats
    logger.info("=== RÉSUMÉ DES TESTS ===")
    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result)
    
    for test_name, result in results.items():
        status = "✅ PASSÉ" if result else "❌ ÉCHOUÉ"
        logger.info(f"{test_name.capitalize()}: {status}")
    
    success_rate = (passed_tests / total_tests) * 100
    logger.info(f"Taux de réussite: {passed_tests}/{total_tests} ({success_rate:.1f}%)")
    
    if passed_tests == total_tests:
        print("\n🎉 TOUS LES TESTS ONT RÉUSSI !")
        print("La migration PostgreSQL est fonctionnelle.")
        return True
    else:
        print(f"\n⚠️  {total_tests - passed_tests} test(s) ont échoué")
        print("Veuillez vérifier les logs pour plus de détails.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)