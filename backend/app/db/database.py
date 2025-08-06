"""
Module de gestion de base de données PostgreSQL unifié pour Gilbert
Remplace l'ancien système SQLite et unifie les connexions PostgreSQL
"""

import psycopg2
import psycopg2.extras
import psycopg2.pool
import os
from datetime import datetime
import logging
from typing import Optional, Dict, Any, List
import json
import threading
import time
from contextlib import contextmanager

# Configuration du logging
logger = logging.getLogger(__name__)

# Configuration PostgreSQL avec fallback
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://gilbert_user:gilbertmdp2025@postgres:5432/gilbert_db"
)

# Pool de connexions global
_connection_pool = None
_pool_lock = threading.Lock()

class DatabaseError(Exception):
    """Exception personnalisée pour les erreurs de base de données"""
    pass

def initialize_connection_pool(min_conn=1, max_conn=20):
    """Initialise le pool de connexions PostgreSQL"""
    global _connection_pool
    
    if _connection_pool is not None:
        return _connection_pool
        
    try:
        with _pool_lock:
            if _connection_pool is None:
                logger.info(f"Initialisation du pool de connexions PostgreSQL (min={min_conn}, max={max_conn})")
                _connection_pool = psycopg2.pool.ThreadedConnectionPool(
                    min_conn, max_conn, DATABASE_URL
                )
                logger.info("Pool de connexions PostgreSQL initialisé avec succès")
        return _connection_pool
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation du pool de connexions: {e}")
        raise DatabaseError(f"Impossible d'initialiser le pool de connexions: {e}")

def get_db_connection():
    """
    Obtenir une connexion PostgreSQL depuis le pool
    Utilise le pool si disponible, sinon crée une connexion directe
    """
    global _connection_pool
    
    # Initialiser le pool si nécessaire
    if _connection_pool is None:
        initialize_connection_pool()
    
    try:
        if _connection_pool:
            conn = _connection_pool.getconn()
            if conn:
                # Vérifier si la connexion est toujours valide
                if conn.closed:
                    logger.warning("Connexion fermée détectée, création d'une nouvelle connexion")
                    _connection_pool.putconn(conn, close=True)
                    conn = _connection_pool.getconn()
                return conn
    except Exception as e:
        logger.warning(f"Erreur avec le pool de connexions, connexion directe: {e}")
    
    # Fallback : connexion directe
    try:
        conn = psycopg2.connect(DATABASE_URL)
        logger.debug("Connexion directe PostgreSQL établie")
        return conn
    except Exception as e:
        logger.error(f"Erreur de connexion PostgreSQL: {e}")
        raise DatabaseError(f"Impossible de se connecter à PostgreSQL: {e}")

def release_db_connection(conn, close=False):
    """
    Libère une connexion dans le pool ou la ferme
    """
    global _connection_pool
    
    if not conn:
        return
        
    try:
        if _connection_pool and not close and not conn.closed:
            _connection_pool.putconn(conn)
            logger.debug("Connexion retournée au pool")
        else:
            conn.close()
            logger.debug("Connexion fermée directement")
    except Exception as e:
        logger.error(f"Erreur lors de la libération de la connexion: {e}")
        try:
            conn.close()
        except:
            pass

def reset_db_pool():
    """Réinitialise le pool de connexions en cas de problème"""
    global _connection_pool
    
    with _pool_lock:
        if _connection_pool:
            try:
                _connection_pool.closeall()
                logger.info("Pool de connexions fermé")
            except Exception as e:
                logger.error(f"Erreur lors de la fermeture du pool: {e}")
            finally:
                _connection_pool = None
        
        # Réinitialiser le pool
        try:
            initialize_connection_pool()
            logger.info("Pool de connexions réinitialisé")
        except Exception as e:
            logger.error(f"Erreur lors de la réinitialisation du pool: {e}")

@contextmanager
def get_db_cursor(dict_cursor=True):
    """
    Context manager pour obtenir un curseur de base de données
    Gère automatiquement la connexion et la libération des ressources
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if dict_cursor:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cursor = conn.cursor()
        yield cursor, conn
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Erreur dans la transaction de base de données: {e}")
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn)

# =============================================================================
# FONCTIONS UTILITAIRES DE BASE DE DONNÉES
# =============================================================================

def execute_query(query: str, params: tuple = None, fetch=False, dict_cursor=True) -> Any:
    """
    Exécute une requête SQL et retourne le résultat
    """
    with get_db_cursor(dict_cursor=dict_cursor) as (cursor, conn):
        cursor.execute(query, params or ())
        
        if fetch == 'one':
            result = cursor.fetchone()
            return dict(result) if result and dict_cursor else result
        elif fetch == 'all':
            results = cursor.fetchall()
            return [dict(r) for r in results] if results and dict_cursor else results
        elif fetch:
            return cursor.fetchall()
        else:
            conn.commit()
            return cursor.rowcount

def check_table_exists(table_name: str) -> bool:
    """Vérifie si une table existe"""
    try:
        query = """
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = %s
            );
        """
        result = execute_query(query, (table_name,), fetch='one', dict_cursor=False)
        return result[0] if result else False
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de l'existence de la table {table_name}: {e}")
        return False

def get_table_schema(table_name: str) -> List[Dict]:
    """Récupère le schéma d'une table"""
    try:
        query = """
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
            ORDER BY ordinal_position;
        """
        return execute_query(query, (table_name,), fetch='all')
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du schéma de la table {table_name}: {e}")
        return []

# =============================================================================
# FONCTIONS SPÉCIFIQUES AUX UTILISATEURS
# =============================================================================

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Récupérer un utilisateur par email"""
    try:
        query = "SELECT * FROM users WHERE email = %s"
        result = execute_query(query, (email,), fetch='one')
        
        if result:
            # Normaliser les champs pour compatibilité
            if 'first_name' in result and 'last_name' in result:
                result['full_name'] = f"{result['first_name']} {result['last_name']}".strip()
            
            # Convertir l'ID en string pour compatibilité
            result['id'] = str(result['id'])
            
            return result
        return None
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'utilisateur par email {email}: {e}")
        raise DatabaseError(f"Erreur lors de la récupération de l'utilisateur: {e}")

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Récupérer un utilisateur par ID"""
    try:
        query = "SELECT * FROM users WHERE id = %s"
        result = execute_query(query, (user_id,), fetch='one')
        
        if result:
            # Normaliser les champs pour compatibilité
            if 'first_name' in result and 'last_name' in result:
                result['full_name'] = f"{result['first_name']} {result['last_name']}".strip()
            
            # Convertir l'ID en string pour compatibilité
            result['id'] = str(result['id'])
            
            return result
        return None
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'utilisateur par ID {user_id}: {e}")
        raise DatabaseError(f"Erreur lors de la récupération de l'utilisateur: {e}")

def create_user(user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Créer un nouvel utilisateur"""
    try:
        # Extraire le nom complet
        full_name = user_data.get("full_name", "")
        first_name = ""
        last_name = ""
        
        if full_name:
            name_parts = full_name.split(" ", 1)
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ""
        
        query = """
            INSERT INTO users (email, password_hash, first_name, last_name, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, email, first_name, last_name, created_at
        """
        params = (
            user_data["email"],
            user_data["hashed_password"],
            first_name,
            last_name,
            datetime.utcnow(),
            datetime.utcnow()
        )
        
        result = execute_query(query, params, fetch='one')
        
        if result:
            # Normaliser pour compatibilité
            result['full_name'] = f"{result['first_name']} {result['last_name']}".strip()
            result['id'] = str(result['id'])
            if result['created_at']:
                result['created_at'] = result['created_at'].isoformat()
            return result
        
        return None
        
    except Exception as e:
        logger.error(f"Erreur lors de la création de l'utilisateur: {e}")
        raise DatabaseError(f"Erreur lors de la création de l'utilisateur: {e}")

def update_user(user_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Mettre à jour un utilisateur"""
    try:
        # Construire la requête de mise à jour
        set_clauses = []
        values = []
        
        # Gérer le nom complet
        if 'full_name' in update_data:
            full_name = update_data['full_name']
            name_parts = full_name.split(" ", 1) if full_name else ["", ""]
            update_data['first_name'] = name_parts[0]
            update_data['last_name'] = name_parts[1] if len(name_parts) > 1 else ""
            del update_data['full_name']
        
        for key, value in update_data.items():
            if key not in ['id', 'created_at']:  # Éviter de modifier les champs immutables
                set_clauses.append(f"{key} = %s")
                values.append(value)
        
        if not set_clauses:
            return get_user_by_id(user_id)
        
        values.extend([datetime.utcnow(), user_id])
        
        query = f"""
            UPDATE users 
            SET {', '.join(set_clauses)}, updated_at = %s
            WHERE id = %s
            RETURNING *
        """
        
        result = execute_query(query, tuple(values), fetch='one')
        
        if result:
            # Normaliser pour compatibilité
            if 'first_name' in result and 'last_name' in result:
                result['full_name'] = f"{result['first_name']} {result['last_name']}".strip()
            result['id'] = str(result['id'])
            return result
        
        return None
        
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de l'utilisateur {user_id}: {e}")
        raise DatabaseError(f"Erreur lors de la mise à jour de l'utilisateur: {e}")

# =============================================================================
# FONCTIONS DE GESTION DES MOTS DE PASSE
# =============================================================================

import bcrypt

def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    except Exception:
        return False

# =============================================================================
# INITIALISATION ET TESTS
# =============================================================================

def test_connection():
    """Teste la connexion à la base de données"""
    try:
        with get_db_cursor() as (cursor, conn):
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            logger.info("Test de connexion PostgreSQL réussi")
            return True
    except Exception as e:
        logger.error(f"Test de connexion PostgreSQL échoué: {e}")
        return False

def initialize_database():
    """Initialise la base de données et vérifie les tables"""
    try:
        # Tester la connexion
        if not test_connection():
            raise DatabaseError("Impossible de se connecter à la base de données")
        
        # Vérifier les tables principales
        required_tables = ['users', 'meetings']
        missing_tables = []
        
        for table in required_tables:
            if not check_table_exists(table):
                missing_tables.append(table)
        
        if missing_tables:
            logger.warning(f"Tables manquantes détectées: {missing_tables}")
            logger.info("Exécutez le script d'initialisation SQL pour créer les tables manquantes")
        
        # Initialiser le pool
        initialize_connection_pool()
        
        logger.info("Base de données Gilbert initialisée avec succès")
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation de la base de données: {e}")
        raise DatabaseError(f"Erreur lors de l'initialisation: {e}")

# Initialisation automatique
if __name__ != "__main__":
    try:
        initialize_database()
    except Exception as e:
        logger.warning(f"Initialisation automatique échouée: {e}")