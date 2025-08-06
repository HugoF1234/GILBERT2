# Module seed pour créer des utilisateurs par défaut
import logging
from .database import execute_query
from ..core.security import get_password_hash

logger = logging.getLogger(__name__)

def create_default_users():
    """Créer des utilisateurs par défaut si ils n'existent pas"""
    try:
        # Vérifier si des utilisateurs existent déjà
        existing_users = execute_query("SELECT COUNT(*) as count FROM users", fetch='one')
        
        if existing_users and existing_users['count'] > 0:
            logger.info("Des utilisateurs existent déjà, pas de création d'utilisateurs par défaut")
            return
        
        # Créer l'utilisateur admin par défaut
        admin_password = get_password_hash("admin123")
        admin_query = """
            INSERT INTO users (email, hashed_password, full_name, is_active, is_superuser, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
            ON CONFLICT (email) DO NOTHING
        """
        
        execute_query(admin_query, (
            "admin@gilbert.local",
            admin_password,
            "Administrateur Gilbert",
            True,
            True
        ))
        
        # Créer un utilisateur de test
        test_password = get_password_hash("test123")
        test_query = """
            INSERT INTO users (email, hashed_password, full_name, is_active, is_superuser, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
            ON CONFLICT (email) DO NOTHING
        """
        
        execute_query(test_query, (
            "test@gilbert.local",
            test_password,
            "Utilisateur Test",
            True,
            False
        ))
        
        logger.info("Utilisateurs par défaut créés avec succès")
        
    except Exception as e:
        logger.error(f"Erreur lors de la création des utilisateurs par défaut: {e}")
        # Ne pas faire planter l'application pour ça
        pass