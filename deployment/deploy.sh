#!/bin/bash

# Script de déploiement automatique pour Gilbert
# VPS OVH - Production

set -e

echo "🚀 Déploiement de Gilbert en production"
echo "======================================="

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérification du fichier .env
if [ ! -f ".env" ]; then
    log_error "Fichier .env manquant !"
    echo "Copiez env.example vers .env et configurez les variables :"
    echo "cp env.example .env"
    echo "nano .env"
    exit 1
fi

# Charger les variables d'environnement
source .env

# Vérification des variables critiques
if [ -z "$DOMAIN_NAME" ] || [ "$DOMAIN_NAME" = "votre-domaine.com" ]; then
    log_error "DOMAIN_NAME non configuré dans .env"
    exit 1
fi

if [ -z "$POSTGRES_PASSWORD" ] || [ "$POSTGRES_PASSWORD" = "votre_mot_de_passe_postgres_super_securise" ]; then
    log_error "POSTGRES_PASSWORD non configuré dans .env"
    exit 1
fi

if [ -z "$JWT_SECRET" ] || [ "$JWT_SECRET" = "votre_jwt_secret_super_securise_et_long" ]; then
    log_error "JWT_SECRET non configuré dans .env"
    exit 1
fi

# Arrêt des services existants
log_info "Arrêt des services existants..."
docker-compose -f docker-compose.production.yml down || true

# Nettoyage des images anciennes
log_info "Nettoyage des images Docker..."
docker system prune -f

# Construction et démarrage des services
log_info "Construction et démarrage des services..."
docker-compose -f docker-compose.production.yml up -d --build

# Attendre que les services soient prêts
log_info "Attente du démarrage des services..."
sleep 30

# Vérification de la santé des services
log_info "Vérification de la santé des services..."

# Vérifier PostgreSQL
if docker-compose -f docker-compose.production.yml exec -T postgres pg_isready -U gilbert_user -d gilbert_db; then
    log_info "✅ PostgreSQL est prêt"
else
    log_error "❌ PostgreSQL n'est pas prêt"
    exit 1
fi

# Vérifier Redis
if docker-compose -f docker-compose.production.yml exec -T redis redis-cli ping | grep -q "PONG"; then
    log_info "✅ Redis est prêt"
else
    log_error "❌ Redis n'est pas prêt"
    exit 1
fi

# Vérifier l'API
if curl -f http://localhost:8000/health > /dev/null 2>&1; then
    log_info "✅ API est prête"
else
    log_warn "⚠️ API n'est pas encore prête, attente..."
    sleep 30
    if curl -f http://localhost:8000/health > /dev/null 2>&1; then
        log_info "✅ API est maintenant prête"
    else
        log_error "❌ API n'est toujours pas prête"
        exit 1
    fi
fi

# Configuration SSL avec Let's Encrypt
log_info "Configuration SSL avec Let's Encrypt..."

# Vérifier si le certificat existe déjà
if [ ! -f "certbot/conf/live/$DOMAIN_NAME/fullchain.pem" ]; then
    log_info "Génération du certificat SSL..."
    
    # Arrêter temporairement Nginx pour le challenge
    docker-compose -f docker-compose.production.yml stop nginx
    
    # Générer le certificat
    docker-compose -f docker-compose.production.yml run --rm certbot
    
    # Redémarrer Nginx
    docker-compose -f docker-compose.production.yml start nginx
else
    log_info "Certificat SSL déjà existant"
fi

# Vérification finale
log_info "Vérification finale..."

# Vérifier que Nginx fonctionne
if curl -f -k https://localhost/health > /dev/null 2>&1; then
    log_info "✅ Nginx fonctionne correctement"
else
    log_warn "⚠️ Nginx n'est pas encore prêt"
fi

# Affichage des informations de déploiement
echo ""
echo "🎉 Déploiement terminé avec succès !"
echo ""
echo "📊 Informations de déploiement :"
echo "- URL de l'application : https://$DOMAIN_NAME"
echo "- URL de l'API : https://$DOMAIN_NAME/api"
echo "- Documentation API : https://$DOMAIN_NAME/api/docs"
echo ""
echo "🔧 Commandes utiles :"
echo "- Voir les logs : docker-compose -f docker-compose.production.yml logs -f"
echo "- Redémarrer : docker-compose -f docker-compose.production.yml restart"
echo "- Arrêter : docker-compose -f docker-compose.production.yml down"
echo "- Mettre à jour : git pull && ./deploy.sh"
echo ""
echo "📈 Monitoring :"
echo "- Utilisation des ressources : htop"
echo "- Logs Nginx : sudo tail -f /var/log/nginx/access.log"
echo "- Logs Docker : docker-compose -f docker-compose.production.yml logs -f"
echo ""
echo "🔒 Sécurité :"
echo "- Firewall configuré : sudo ufw status"
echo "- Fail2ban actif : sudo fail2ban-client status"
echo "- Certificat SSL valide jusqu'au : $(openssl x509 -in certbot/conf/live/$DOMAIN_NAME/fullchain.pem -text -noout | grep 'Not After')" 