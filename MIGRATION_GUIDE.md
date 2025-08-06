# 🔄 Guide de Migration SQLite → PostgreSQL pour Gilbert

Ce guide vous aidera à corriger les problèmes de migration de votre application Gilbert de SQLite vers PostgreSQL.

## 🚨 Problèmes identifiés

1. **Incohérences dans les schémas de base de données**
   - Deux schémas différents (`backend/init.sql` vs `deployment/init.sql`)
   - Types d'ID différents (UUID vs SERIAL)
   - Colonnes manquantes

2. **Références à des modules inexistants**
   - Imports vers `app.db.database` qui n'existait pas
   - Mélanges entre `postgresql_db.py` et `postgresql_queries.py`

3. **Signatures de fonctions incompatibles**
   - Paramètres manquants (ex: `user_id` dans `update_meeting`)
   - Retours de fonction incohérents

## ✅ Solutions implémentées

### 1. Nouveau système de base de données unifié

**Fichiers créés/modifiés :**
- `backend/app/db/database.py` - Module principal avec pool de connexions
- `backend/app/db/queries.py` - Requêtes unifiées et compatibles
- `backend/init_schema.sql` - Schéma PostgreSQL unifié

### 2. Corrections des imports

**Avant :**
```python
from ..db.postgresql_queries import update_meeting
from ..db.database import get_db_connection  # N'existait pas
```

**Après :**
```python
from ..db.queries import update_meeting
from ..db.database import get_db_connection  # Maintenant disponible
```

### 3. Pool de connexions optimisé

- Connexions réutilisables avec pool ThreadedConnectionPool
- Gestion automatique des timeouts et reconnexions
- Fallback sur connexions directes si le pool échoue

## 🛠️ Instructions de migration

### Étape 1: Sauvegarder les données existantes

```bash
# Sur votre serveur OVH
pg_dump -h localhost -U gilbert_user gilbert_db > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Étape 2: Appliquer les corrections

```bash
cd /path/to/your/gilbert/backend

# 1. Exécuter le script de migration
python migrate_database.py

# 2. Tester la migration
python test_migration.py
```

### Étape 3: Vérifier les services

```bash
# Redémarrer l'application
sudo systemctl restart gilbert-api  # ou votre service

# Vérifier les logs
tail -f /var/log/gilbert/api.log
```

## 🗄️ Nouveau schéma de base de données

### Tables principales :

```sql
-- Utilisateurs
users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    profile_picture_url TEXT,
    oauth_provider VARCHAR(50),
    oauth_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE
)

-- Réunions
meetings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    title VARCHAR(255),
    file_url TEXT,
    transcript_text TEXT,
    transcript_status VARCHAR(50) DEFAULT 'pending',
    transcript_id VARCHAR(255),  -- ID AssemblyAI
    duration_seconds INTEGER,
    speakers_count INTEGER,
    summary_text TEXT,
    summary_status VARCHAR(50) DEFAULT 'not_generated',
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE
)

-- Locuteurs
speakers (
    id SERIAL PRIMARY KEY,
    meeting_id INTEGER REFERENCES meetings(id),
    speaker_id VARCHAR(10),  -- A, B, C, etc.
    custom_name VARCHAR(255),
    confidence FLOAT,
    created_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE
)
```

## 🔧 API mise à jour

### Nouvelles signatures de fonctions :

```python
# Ancien
update_meeting(meeting_id, update_data)

# Nouveau
update_meeting(meeting_id, user_id, update_data)

# Ancien
get_meeting(meeting_id)

# Nouveau  
get_meeting(meeting_id, user_id=None)
```

## 🧪 Tests disponibles

### Test de connexion :
```bash
python -c "from app.db.database import test_connection; print('✅ OK' if test_connection() else '❌ Erreur')"
```

### Test complet :
```bash
python test_migration.py
```

## 🚀 Variables d'environnement

Assurez-vous que ces variables sont définies :

```bash
# PostgreSQL
DATABASE_URL=postgresql://gilbert_user:gilbertmdp2025@postgres:5432/gilbert_db

# APIs externes
ASSEMBLYAI_API_KEY=votre_clé_assemblyai
MISTRAL_API_KEY=votre_clé_mistral
JWT_SECRET=votre_secret_jwt
```

## 🔍 Diagnostic des problèmes

### Problème : "module 'app.db.database' n'existe pas"
**Solution :** Le nouveau fichier `database.py` résout ce problème

### Problème : "missing 1 required positional argument: 'user_id'"
**Solution :** Les fonctions ont été mises à jour avec les bons paramètres

### Problème : "relation 'meetings' does not exist"
**Solution :** Exécuter `migrate_database.py` pour créer les tables

### Problème : "column 'transcript_id' does not exist"
**Solution :** Le script de migration ajoute automatiquement les colonnes manquantes

## 📊 Monitoring post-migration

```bash
# Vérifier les connexions PostgreSQL
sudo -u postgres psql -c "SELECT count(*) FROM pg_stat_activity WHERE datname='gilbert_db';"

# Vérifier les tables
sudo -u postgres psql gilbert_db -c "\dt"

# Vérifier les données
sudo -u postgres psql gilbert_db -c "SELECT COUNT(*) FROM users; SELECT COUNT(*) FROM meetings;"
```

## 🆘 Support

Si vous rencontrez des problèmes :

1. **Vérifiez les logs** : `tail -f /var/log/postgresql/postgresql-*.log`
2. **Testez la connexion** : `python test_migration.py`
3. **Sauvegardez d'abord** : Ne jamais migrer sans backup !

## ✅ Checklist post-migration

- [ ] Tests de connexion PostgreSQL réussis
- [ ] Authentification fonctionnelle
- [ ] Upload de fichiers audio fonctionnel
- [ ] Transcription AssemblyAI opérationnelle
- [ ] Interface frontend accessible
- [ ] Pas d'erreurs dans les logs

---

**Note importante :** Cette migration corrige les incohérences entre SQLite et PostgreSQL tout en maintenant la compatibilité avec l'API existante.