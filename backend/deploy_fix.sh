#!/bin/bash

# Script de déploiement rapide pour corriger la migration PostgreSQL
# À exécuter sur votre serveur OVH

set -e

echo "🚀 Déploiement des corrections PostgreSQL pour Gilbert"
echo "======================================================="

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

# Vérification des prérequis
log_info "Vérification des prérequis..."

# Vérifier que nous sommes dans le bon répertoire
if [ ! -f "app/main.py" ]; then
    log_error "Ce script doit être exécuté depuis le répertoire backend de Gilbert"
    exit 1
fi

# Vérifier que PostgreSQL est en cours d'exécution
if ! pg_isready -h localhost -p 5432 -U gilbert_user -d gilbert_db > /dev/null 2>&1; then
    log_error "PostgreSQL n'est pas accessible. Vérifiez que le service est démarré."
    exit 1
fi

log_info "✅ Prérequis validés"

# Sauvegarder la base de données existante
log_info "Sauvegarde de la base de données..."
BACKUP_FILE="backup_gilbert_$(date +%Y%m%d_%H%M%S).sql"
if pg_dump -h localhost -U gilbert_user gilbert_db > "$BACKUP_FILE" 2>/dev/null; then
    log_info "✅ Sauvegarde créée: $BACKUP_FILE"
else
    log_warn "⚠️ Échec de la sauvegarde, mais continue..."
fi

# Arrêter le service Gilbert si il est en cours d'exécution
log_info "Arrêt du service Gilbert..."
if systemctl is-active --quiet gilbert-api 2>/dev/null; then
    sudo systemctl stop gilbert-api
    log_info "✅ Service Gilbert arrêté"
elif pgrep -f "python.*gilbert\|python.*app.main" > /dev/null; then
    log_warn "⚠️ Processus Gilbert détecté, tentative d'arrêt..."
    pkill -f "python.*gilbert\|python.*app.main" || true
    sleep 2
fi

# Installer les dépendances Python si nécessaire
log_info "Vérification des dépendances Python..."
if [ -f "requirements.txt" ]; then
    if [ -d "venv" ]; then
        source venv/bin/activate
        pip install -r requirements.txt > /dev/null 2>&1
        log_info "✅ Dépendances mises à jour"
    else
        log_warn "⚠️ Environnement virtuel non trouvé"
    fi
fi

# Exécuter la migration de la base de données
log_info "Exécution de la migration PostgreSQL..."
if python migrate_database.py; then
    log_info "✅ Migration PostgreSQL réussie"
else
    log_error "❌ Échec de la migration PostgreSQL"
    
    # Restaurer la sauvegarde si elle existe
    if [ -f "$BACKUP_FILE" ]; then
        log_info "Restauration de la sauvegarde..."
        dropdb -h localhost -U gilbert_user gilbert_db --if-exists
        createdb -h localhost -U gilbert_user gilbert_db
        psql -h localhost -U gilbert_user gilbert_db < "$BACKUP_FILE" > /dev/null 2>&1
        log_info "Base de données restaurée"
    fi
    
    exit 1
fi

# Tester la migration
log_info "Test de la migration..."
if python test_migration.py; then
    log_info "✅ Tests de migration réussis"
else
    log_error "❌ Échec des tests de migration"
    exit 1
fi

# Redémarrer le service Gilbert
log_info "Redémarrage du service Gilbert..."

# Méthode 1: systemctl (si configuré)
if systemctl list-unit-files | grep -q gilbert-api; then
    sudo systemctl start gilbert-api
    sleep 5
    if systemctl is-active --quiet gilbert-api; then
        log_info "✅ Service Gilbert redémarré avec systemctl"
    else
        log_warn "⚠️ Échec du redémarrage avec systemctl"
    fi
else
    # Méthode 2: démarrage direct avec gunicorn
    log_info "Démarrage direct avec gunicorn..."
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    # Démarrer en arrière-plan
    nohup gunicorn -w 2 --timeout 300 --bind 0.0.0.0:8000 app.main:app > gilbert.log 2>&1 &
    sleep 5
    
    if pgrep -f "gunicorn.*app.main" > /dev/null; then
        log_info "✅ Gilbert démarré avec gunicorn"
    else
        log_error "❌ Échec du démarrage de Gilbert"
        exit 1
    fi
fi

# Test de santé de l'API
log_info "Test de santé de l'API..."
sleep 10  # Attendre que l'API soit prête

for i in {1..5}; do
    if curl -f http://localhost:8000/health > /dev/null 2>&1; then
        log_info "✅ API Gilbert opérationnelle"
        break
    else
        log_warn "⚠️ Tentative $i/5: API non accessible, attente..."
        sleep 10
    fi
    
    if [ $i -eq 5 ]; then
        log_error "❌ API Gilbert non accessible après 5 tentatives"
        exit 1
    fi
done

# Nettoyage des anciens backups (garder les 5 plus récents)
log_info "Nettoyage des anciens backups..."
ls -t backup_gilbert_*.sql 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true

# Affichage du résumé
echo ""
echo "🎉 Déploiement terminé avec succès !"
echo ""
echo "📊 Résumé :"
echo "- Base de données PostgreSQL migrée"
echo "- API Gilbert opérationnelle"
echo "- Sauvegarde créée: $BACKUP_FILE"
echo ""
echo "🔗 URLs :"
echo "- API Health: http://localhost:8000/health"
echo "- Documentation: http://localhost:8000/docs"
echo ""
echo "📋 Commandes utiles :"
echo "- Voir les logs: tail -f gilbert.log"
echo "- Redémarrer: sudo systemctl restart gilbert-api"
echo "- Statut: sudo systemctl status gilbert-api"
echo ""
echo "✅ Migration PostgreSQL terminée avec succès !"