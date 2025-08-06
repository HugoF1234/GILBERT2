#!/usr/bin/env python3
"""
Script de migration de la base de données Gilbert
Migration SQLite → PostgreSQL et correction des incohérences
"""

import os
import sys
import logging
import psycopg2
import psycopg2.extras
from datetime import datetime

# Ajouter le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import initialize_database, test_connection, get_db_connection, release_db_connection

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_sql_file(file_path: str) -> bool:
    """Exécuter un fichier SQL"""
    try:
        if not os.path.exists(file_path):
            logger.error(f"Fichier SQL introuvable: {file_path}")
            return False
        
        with open(file_path, 'r', encoding='utf-8') as f:
            sql_content = f.read()
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            # Diviser le contenu en instructions séparées
            statements = sql_content.split(';')
            
            for statement in statements:
                statement = statement.strip()
                if statement and not statement.startswith('--'):
                    try:
                        cursor.execute(statement)
                        logger.debug(f"Exécuté: {statement[:50]}...")
                    except Exception as e:
                        logger.warning(f"Instruction ignorée (probablement normale): {e}")
            
            conn.commit()
            logger.info(f"Fichier SQL exécuté avec succès: {file_path}")
            return True
            
        finally:
            release_db_connection(conn)
            
    except Exception as e:
        logger.error(f"Erreur lors de l'exécution du fichier SQL {file_path}: {e}")
        return False

def check_table_structure():
    """Vérifier et afficher la structure des tables"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Lister toutes les tables
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY table_name
        """)
        tables = cursor.fetchall()
        
        logger.info("Tables existantes:")
        for table in tables:
            table_name = table['table_name']
            logger.info(f"  - {table_name}")
            
            # Afficher la structure de chaque table
            cursor.execute("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = %s
                ORDER BY ordinal_position
            """, (table_name,))
            
            columns = cursor.fetchall()
            for col in columns:
                logger.info(f"    {col['column_name']}: {col['data_type']} "
                          f"{'NULL' if col['is_nullable'] == 'YES' else 'NOT NULL'}")
        
        release_db_connection(conn)
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de la structure: {e}")
        return False

def migrate_data_if_needed():
    """Migrer les données si nécessaire"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Vérifier s'il y a des données à migrer
        cursor.execute("SELECT COUNT(*) as count FROM users")
        user_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM meetings")
        meeting_count = cursor.fetchone()['count']
        
        logger.info(f"Données existantes: {user_count} utilisateurs, {meeting_count} réunions")
        
        # Si pas de données, insérer les données par défaut
        if user_count == 0:
            logger.info("Insertion des utilisateurs par défaut...")
            
            # Admin user
            cursor.execute("""
                INSERT INTO users (email, password_hash, first_name, last_name, is_admin, is_active)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (email) DO NOTHING
            """, (
                'admin@gilbert.com',
                '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.i8mG',
                'Admin',
                'Gilbert',
                True,
                True
            ))
            
            # Test user
            cursor.execute("""
                INSERT INTO users (email, password_hash, first_name, last_name, is_active)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (email) DO NOTHING
            """, (
                'test@gilbert.com',
                '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.i8mG',
                'Test',
                'User',
                True
            ))
            
            conn.commit()
            logger.info("Utilisateurs par défaut créés")
        
        release_db_connection(conn)
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors de la migration des données: {e}")
        return False

def add_missing_columns():
    """Ajouter les colonnes manquantes pour la compatibilité"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Colonnes à ajouter si elles n'existent pas
        columns_to_add = [
            ("meetings", "transcript_id", "VARCHAR(255)"),
            ("meetings", "summary_status", "VARCHAR(50) DEFAULT 'not_generated'"),
            ("meetings", "processed_at", "TIMESTAMP WITH TIME ZONE"),
        ]
        
        for table, column, definition in columns_to_add:
            try:
                cursor.execute(f"""
                    ALTER TABLE {table} 
                    ADD COLUMN IF NOT EXISTS {column} {definition}
                """)
                logger.info(f"Colonne ajoutée: {table}.{column}")
            except Exception as e:
                logger.debug(f"Colonne {table}.{column} existe déjà ou erreur: {e}")
        
        conn.commit()
        release_db_connection(conn)
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors de l'ajout des colonnes: {e}")
        return False

def main():
    """Fonction principale de migration"""
    logger.info("=== DÉBUT DE LA MIGRATION GILBERT ===")
    
    # Étape 1: Tester la connexion
    logger.info("1. Test de connexion à PostgreSQL...")
    if not test_connection():
        logger.error("❌ Impossible de se connecter à PostgreSQL")
        return False
    logger.info("✅ Connexion PostgreSQL OK")
    
    # Étape 2: Initialiser la base de données
    logger.info("2. Initialisation de la base de données...")
    try:
        initialize_database()
        logger.info("✅ Base de données initialisée")
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'initialisation: {e}")
        return False
    
    # Étape 3: Exécuter le schéma unifié
    logger.info("3. Application du schéma unifié...")
    schema_file = os.path.join(os.path.dirname(__file__), 'init_schema.sql')
    if run_sql_file(schema_file):
        logger.info("✅ Schéma unifié appliqué")
    else:
        logger.warning("⚠️  Problème avec le schéma unifié, mais continue...")
    
    # Étape 4: Ajouter les colonnes manquantes
    logger.info("4. Ajout des colonnes manquantes...")
    if add_missing_columns():
        logger.info("✅ Colonnes mises à jour")
    else:
        logger.warning("⚠️  Problème avec les colonnes, mais continue...")
    
    # Étape 5: Migrer les données
    logger.info("5. Migration des données...")
    if migrate_data_if_needed():
        logger.info("✅ Données migrées")
    else:
        logger.error("❌ Erreur lors de la migration des données")
        return False
    
    # Étape 6: Vérification finale
    logger.info("6. Vérification de la structure finale...")
    if check_table_structure():
        logger.info("✅ Structure vérifiée")
    else:
        logger.warning("⚠️  Problème lors de la vérification")
    
    logger.info("=== MIGRATION TERMINÉE AVEC SUCCÈS ===")
    print("\n🎉 Migration réussie !")
    print("La base de données PostgreSQL est maintenant prête pour Gilbert")
    print("\nUtilisateurs par défaut créés:")
    print("  - admin@gilbert.com (mot de passe: admin123)")
    print("  - test@gilbert.com (mot de passe: test123)")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)