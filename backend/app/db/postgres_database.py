import asyncpg
import asyncio
import os
import bcrypt
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
import redis.asyncio as redis
from contextlib import asynccontextmanager
import logging
from ..core.config import settings

logger = logging.getLogger(__name__)

# Pool de connexions PostgreSQL
_pool: Optional[asyncpg.Pool] = None
_redis_client: Optional[redis.Redis] = None

async def get_postgres_pool() -> asyncpg.Pool:
    """Obtenir le pool de connexions PostgreSQL"""
    global _pool
    if _pool is None:
        try:
            _pool = await asyncpg.create_pool(
                settings.DATABASE_URL,
                min_size=5,
                max_size=settings.DB_POOL_SIZE,
                command_timeout=settings.DB_POOL_TIMEOUT
            )
            logger.info("✅ Pool PostgreSQL créé avec succès")
        except Exception as e:
            logger.error(f"❌ Erreur lors de la création du pool PostgreSQL: {e}")
            raise
    return _pool

async def get_redis_client() -> redis.Redis:
    """Obtenir le client Redis"""
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                max_connections=20
            )
            # Test de connexion
            await _redis_client.ping()
            logger.info("✅ Client Redis connecté avec succès")
        except Exception as e:
            logger.error(f"❌ Erreur lors de la connexion à Redis: {e}")
            # Fallback: pas de cache si Redis n'est pas disponible
            _redis_client = None
    return _redis_client

@asynccontextmanager
async def get_db_connection():
    """Context manager pour obtenir une connexion PostgreSQL"""
    pool = await get_postgres_pool()
    async with pool.acquire() as connection:
        yield connection

async def init_database():
    """Initialiser la base de données PostgreSQL"""
    try:
        pool = await get_postgres_pool()
        async with pool.acquire() as conn:
            # Vérifier si les tables existent
            tables_exist = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'users'
                );
            """)
            
            if not tables_exist:
                logger.info("🔄 Initialisation de la base de données PostgreSQL...")
                # Les tables seront créées par le script init.sql
                logger.info("✅ Base de données PostgreSQL initialisée")
            else:
                logger.info("✅ Base de données PostgreSQL déjà initialisée")
                
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'initialisation de la base de données: {e}")
        raise

def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifier un mot de passe"""
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

async def create_user(user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Créer un nouvel utilisateur"""
    try:
        async with get_db_connection() as conn:
            user_id = str(uuid.uuid4())
            
            result = await conn.fetchrow("""
                INSERT INTO users (id, email, hashed_password, full_name, 
                                 profile_picture_url, oauth_provider, oauth_id, created_at) 
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *
            """, 
                user_id,
                user_data.get("email"),
                user_data.get("hashed_password"),
                user_data.get("full_name"),
                user_data.get("profile_picture_url"),
                user_data.get("oauth_provider"),
                user_data.get("oauth_id"),
                datetime.utcnow()
            )
            
            return dict(result) if result else None
            
    except Exception as e:
        logger.error(f"Erreur lors de la création de l'utilisateur: {e}")
        return None

async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Récupérer un utilisateur par son email"""
    try:
        # Vérifier le cache Redis d'abord
        redis_client = await get_redis_client()
        if redis_client:
            cached_user = await redis_client.get(f"user:email:{email}")
            if cached_user:
                import json
                return json.loads(cached_user)
        
        async with get_db_connection() as conn:
            result = await conn.fetchrow(
                "SELECT * FROM users WHERE email = $1", email
            )
            
            if result:
                user_dict = dict(result)
                # Convertir UUID en string pour la sérialisation
                user_dict['id'] = str(user_dict['id'])
                if user_dict.get('created_at'):
                    user_dict['created_at'] = user_dict['created_at'].isoformat()
                
                # Mettre en cache
                if redis_client:
                    import json
                    await redis_client.setex(
                        f"user:email:{email}", 
                        settings.CACHE_TTL, 
                        json.dumps(user_dict, default=str)
                    )
                
                return user_dict
            
        return None
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'utilisateur par email: {e}")
        return None

async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Récupérer un utilisateur par son ID"""
    try:
        # Vérifier le cache Redis d'abord
        redis_client = await get_redis_client()
        if redis_client:
            cached_user = await redis_client.get(f"user:id:{user_id}")
            if cached_user:
                import json
                return json.loads(cached_user)
        
        async with get_db_connection() as conn:
            result = await conn.fetchrow(
                "SELECT * FROM users WHERE id = $1", uuid.UUID(user_id)
            )
            
            if result:
                user_dict = dict(result)
                # Convertir UUID en string pour la sérialisation
                user_dict['id'] = str(user_dict['id'])
                if user_dict.get('created_at'):
                    user_dict['created_at'] = user_dict['created_at'].isoformat()
                
                # Mettre en cache
                if redis_client:
                    import json
                    await redis_client.setex(
                        f"user:id:{user_id}", 
                        settings.CACHE_TTL, 
                        json.dumps(user_dict, default=str)
                    )
                
                return user_dict
            
        return None
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'utilisateur par ID: {e}")
        return None

async def get_user_by_oauth(oauth_provider: str, oauth_id: str) -> Optional[Dict[str, Any]]:
    """Récupérer un utilisateur par ses identifiants OAuth"""
    try:
        async with get_db_connection() as conn:
            result = await conn.fetchrow(
                "SELECT * FROM users WHERE oauth_provider = $1 AND oauth_id = $2", 
                oauth_provider, oauth_id
            )
            
            if result:
                user_dict = dict(result)
                user_dict['id'] = str(user_dict['id'])
                if user_dict.get('created_at'):
                    user_dict['created_at'] = user_dict['created_at'].isoformat()
                return user_dict
            
        return None
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'utilisateur OAuth: {e}")
        return None

async def update_user(user_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Mettre à jour les informations d'un utilisateur"""
    try:
        async with get_db_connection() as conn:
            # Construire la requête de mise à jour dynamiquement
            set_clauses = []
            values = []
            param_count = 1
            
            for key, value in update_data.items():
                set_clauses.append(f"{key} = ${param_count}")
                values.append(value)
                param_count += 1
            
            query = f"""
                UPDATE users 
                SET {', '.join(set_clauses)}
                WHERE id = ${param_count}
                RETURNING *
            """
            values.append(uuid.UUID(user_id))
            
            result = await conn.fetchrow(query, *values)
            
            if result:
                user_dict = dict(result)
                user_dict['id'] = str(user_dict['id'])
                if user_dict.get('created_at'):
                    user_dict['created_at'] = user_dict['created_at'].isoformat()
                
                # Invalider le cache
                redis_client = await get_redis_client()
                if redis_client:
                    await redis_client.delete(f"user:id:{user_id}")
                    if 'email' in user_dict:
                        await redis_client.delete(f"user:email:{user_dict['email']}")
                
                return user_dict
            
        return None
        
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de l'utilisateur: {e}")
        return None

async def close_connections():
    """Fermer toutes les connexions"""
    global _pool, _redis_client
    
    if _pool:
        await _pool.close()
        _pool = None
        logger.info("✅ Pool PostgreSQL fermé")
    
    if _redis_client:
        await _redis_client.close()
        _redis_client = None
        logger.info("✅ Client Redis fermé")

# Fonctions de compatibilité avec l'ancien système SQLite
def init_db():
    """Fonction de compatibilité - initialise la base de données"""
    asyncio.create_task(init_database())

# Cache utilisateur (maintenu pour compatibilité)
user_cache = {}

def get_user_by_email_cached(email, max_age_seconds=60):
    """Version compatible avec l'ancien système"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(get_user_by_email(email))
    finally:
        loop.close()

def get_user_by_id_cached(user_id, max_age_seconds=300):
    """Version compatible avec l'ancien système"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(get_user_by_id(user_id))
    finally:
        loop.close()

def clear_user_cache():
    """Vider le cache utilisateur"""
    pass  # Redis gère le cache maintenant

def purge_old_entries_from_cache(max_age_seconds=600):
    """Purger les entrées de cache trop anciennes"""
    pass  # Redis gère l'expiration automatiquement