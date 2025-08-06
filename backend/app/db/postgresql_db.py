import psycopg2
import psycopg2.extras
import os
from datetime import datetime
import logging
from typing import Optional, Dict, Any
import bcrypt

# Configuration PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://gilbert_user:gilbertmdp2025@postgres:5432/gilbert_db")

def get_db_connection():
    """Obtenir une connexion PostgreSQL"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        logging.error(f"Erreur de connexion PostgreSQL: {e}")
        raise

def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def create_user(user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Créer un nouvel utilisateur dans PostgreSQL"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Extraire le nom complet
        full_name = user_data.get("full_name", "")
        first_name = ""
        last_name = ""
        
        if full_name:
            name_parts = full_name.split(" ", 1)
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ""
        
        # Insérer l'utilisateur
        cursor.execute(
            """
            INSERT INTO users (email, password_hash, first_name, last_name, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, email, first_name, last_name, created_at
            """,
            (
                user_data["email"],
                user_data["hashed_password"],
                first_name,
                last_name,
                datetime.utcnow(),
                datetime.utcnow()
            )
        )
        
        user = cursor.fetchone()
        conn.commit()
        
        if user:
            return {
                "id": str(user["id"]),
                "email": user["email"],
                "full_name": f"{user['first_name']} {user['last_name']}".strip(),
                "created_at": user["created_at"].isoformat() if user["created_at"] else None
            }
        
        return None
        
    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Erreur lors de la création de l'utilisateur: {e}")
        raise
    finally:
        if conn:
            conn.close()

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Récupérer un utilisateur par email"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute(
            "SELECT id, email, password_hash, first_name, last_name, created_at FROM users WHERE email = %s",
            (email,)
        )
        
        user = cursor.fetchone()
        
        if user:
            return {
                "id": str(user["id"]),
                "email": user["email"],
                "password_hash": user["password_hash"],
                "full_name": f"{user['first_name']} {user['last_name']}".strip(),
                "created_at": user["created_at"].isoformat() if user["created_at"] else None
            }
        
        return None
        
    except Exception as e:
        logging.error(f"Erreur lors de la récupération de l'utilisateur: {e}")
        raise
    finally:
        if conn:
            conn.close()

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Récupérer un utilisateur par ID"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cursor.execute(
            "SELECT id, email, first_name, last_name, created_at FROM users WHERE id = %s",
            (user_id,)
        )
        
        user = cursor.fetchone()
        
        if user:
            return {
                "id": str(user["id"]),
                "email": user["email"],
                "full_name": f"{user['first_name']} {user['last_name']}".strip(),
                "created_at": user["created_at"].isoformat() if user["created_at"] else None
            }
        
        return None
        
    except Exception as e:
        logging.error(f"Erreur lors de la récupération de l'utilisateur: {e}")
        raise
    finally:
        if conn:
            conn.close()

# Cache simple pour les utilisateurs
_user_cache = {}

def get_user_by_email_cached(email: str, max_age_seconds: int = 60) -> Optional[Dict[str, Any]]:
    """Récupérer un utilisateur par email avec cache"""
    current_time = datetime.utcnow()
    
    if email in _user_cache:
        cached_user, cache_time = _user_cache[email]
        if (current_time - cache_time).total_seconds() < max_age_seconds:
            return cached_user
    
    user = get_user_by_email(email)
    if user:
        _user_cache[email] = (user, current_time)
    
    return user

def clear_user_cache():
    """Vider le cache des utilisateurs"""
    global _user_cache
    _user_cache.clear() 