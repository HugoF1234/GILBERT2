#!/bin/bash
set -e

echo "🚀 Démarrage de l'API Gilbert..."

echo "⏳ Attente de PostgreSQL..."
until pg_isready -h postgres -p 5432 -U gilbert_user >/dev/null 2>&1; do
  echo "PostgreSQL n'est pas encore prêt. Attente..."
  sleep 2
done
echo "✅ PostgreSQL est prêt !"

echo "🔄 Initialisation PostgreSQL..."
python - <<'PY'
import asyncio
from app.db.postgres_database import init_database
asyncio.run(init_database())
print("✅ Base de données PostgreSQL initialisée")
PY

echo "🚀 Démarrage de l'API..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1 --log-level info --access-log --use-colors
