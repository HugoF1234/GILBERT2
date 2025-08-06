#!/bin/bash

echo "🚀 Démarrage de l'API Gilbert..."

# Attendre que PostgreSQL soit prêt
echo "⏳ Attente de PostgreSQL..."
while ! pg_isready -h postgres -p 5432 -U gilbert_user; do
    echo "PostgreSQL n'est pas encore prêt. Attente..."
    sleep 2
done

echo "✅ PostgreSQL est prêt !"

# Lancer les migrations si nécessaire
echo "🔄 Vérification de la base de données..."
python -c "
import sys
sys.path.append('/app')
from app.db.database import init_db
try:
    init_db()
    print('✅ Base de données initialisée avec succès')
except Exception as e:
    print(f'❌ Erreur lors de l\'initialisation de la base de données: {e}')
    sys.exit(1)
"

# Démarrer l'application
echo "🚀 Démarrage de l'API..."
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 1 \
    --log-level info \
    --access-log \
    --use-colors