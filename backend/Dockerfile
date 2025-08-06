FROM python:3.9-slim

# Configuration des variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Créer un utilisateur non-root
RUN useradd --create-home --shell /bin/bash app

# Définir le répertoire de travail
WORKDIR /app

# Copier les requirements et installer les dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Créer les répertoires nécessaires
RUN mkdir -p /app/uploads/audio /app/uploads/profile_pictures && \
    chown -R app:app /app

# Copier le code de l'application
COPY --chown=app:app . .

# Passer à l'utilisateur non-root
USER app

# Exposer le port
EXPOSE 8000

# Script de démarrage avec vérification de la base de données
COPY --chown=app:app start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Commande de démarrage
CMD ["/app/start.sh"]