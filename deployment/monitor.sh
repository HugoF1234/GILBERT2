#!/bin/bash

# Script de monitoring pour Gilbert
# VPS OVH - Production

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_header() {
    echo -e "${BLUE}[HEADER]${NC} $1"
}

# Fonction pour vérifier l'état des services Docker
check_docker_services() {
    log_header "Vérification des services Docker"
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose non installé"
        return 1
    fi
    
    cd ~/gilbert
    
    # Vérifier l'état des services
    services_status=$(docker-compose -f docker-compose.production.yml ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}")
    
    echo "$services_status" | while IFS= read -r line; do
        if [[ $line == *"Up"* ]]; then
            log_info "$line"
        elif [[ $line == *"Exit"* ]] || [[ $line == *"Down"* ]]; then
            log_error "$line"
        else
            echo "$line"
        fi
    done
    
    # Vérifier les services critiques
    critical_services=("postgres" "redis" "api" "nginx")
    
    for service in "${critical_services[@]}"; do
        if docker-compose -f docker-compose.production.yml ps | grep -q "$service.*Up"; then
            log_info "✅ $service est en cours d'exécution"
        else
            log_error "❌ $service n'est pas en cours d'exécution"
        fi
    done
}

# Fonction pour vérifier les ressources système
check_system_resources() {
    log_header "Vérification des ressources système"
    
    # CPU
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        log_warn "⚠️ Utilisation CPU élevée: ${cpu_usage}%"
    else
        log_info "✅ Utilisation CPU: ${cpu_usage}%"
    fi
    
    # Mémoire
    memory_info=$(free -h | grep Mem)
    total_mem=$(echo $memory_info | awk '{print $2}')
    used_mem=$(echo $memory_info | awk '{print $3}')
    mem_percent=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
    
    if (( $(echo "$mem_percent > 80" | bc -l) )); then
        log_warn "⚠️ Utilisation mémoire élevée: ${mem_percent}% (${used_mem}/${total_mem})"
    else
        log_info "✅ Utilisation mémoire: ${mem_percent}% (${used_mem}/${total_mem})"
    fi
    
    # Disque
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 80 ]; then
        log_warn "⚠️ Utilisation disque élevée: ${disk_usage}%"
    else
        log_info "✅ Utilisation disque: ${disk_usage}%"
    fi
}

# Fonction pour vérifier la connectivité
check_connectivity() {
    log_header "Vérification de la connectivité"
    
    # Vérifier l'API
    if curl -f http://localhost:8000/health > /dev/null 2>&1; then
        log_info "✅ API accessible localement"
    else
        log_error "❌ API non accessible localement"
    fi
    
    # Vérifier PostgreSQL
    if docker-compose -f docker-compose.production.yml exec -T postgres pg_isready -U gilbert_user -d gilbert_db > /dev/null 2>&1; then
        log_info "✅ PostgreSQL accessible"
    else
        log_error "❌ PostgreSQL non accessible"
    fi
    
    # Vérifier Redis
    if docker-compose -f docker-compose.production.yml exec -T redis redis-cli ping | grep -q "PONG" 2>/dev/null; then
        log_info "✅ Redis accessible"
    else
        log_error "❌ Redis non accessible"
    fi
}

# Fonction pour vérifier les logs d'erreur
check_error_logs() {
    log_header "Vérification des logs d'erreur"
    
    # Logs Docker des dernières 24h
    error_count=$(docker-compose -f docker-compose.production.yml logs --since="24h" 2>&1 | grep -i "error\|exception\|failed" | wc -l)
    
    if [ "$error_count" -gt 10 ]; then
        log_warn "⚠️ Nombre élevé d'erreurs dans les logs Docker: $error_count"
    else
        log_info "✅ Logs Docker: $error_count erreurs dans les dernières 24h"
    fi
    
    # Logs Nginx
    if [ -f "/var/log/nginx/error.log" ]; then
        nginx_errors=$(sudo tail -n 100 /var/log/nginx/error.log | grep -c "error")
        if [ "$nginx_errors" -gt 5 ]; then
            log_warn "⚠️ Erreurs dans les logs Nginx: $nginx_errors"
        else
            log_info "✅ Logs Nginx: $nginx_errors erreurs récentes"
        fi
    fi
}

# Fonction pour vérifier la sécurité
check_security() {
    log_header "Vérification de la sécurité"
    
    # Firewall
    if sudo ufw status | grep -q "Status: active"; then
        log_info "✅ Firewall actif"
    else
        log_error "❌ Firewall inactif"
    fi
    
    # Fail2ban
    if sudo fail2ban-client status | grep -q "Status: Active"; then
        log_info "✅ Fail2ban actif"
    else
        log_error "❌ Fail2ban inactif"
    fi
    
    # Certificat SSL
    if [ -f "certbot/conf/live/$(grep DOMAIN_NAME .env | cut -d'=' -f2)/fullchain.pem" ]; then
        cert_expiry=$(openssl x509 -in certbot/conf/live/$(grep DOMAIN_NAME .env | cut -d'=' -f2)/fullchain.pem -enddate -noout | cut -d'=' -f2)
        log_info "✅ Certificat SSL valide jusqu'au: $cert_expiry"
    else
        log_error "❌ Certificat SSL non trouvé"
    fi
}

# Fonction pour afficher un résumé
show_summary() {
    log_header "Résumé du monitoring"
    
    echo ""
    echo "📊 État général du système:"
    echo "- Services Docker: $(docker-compose -f docker-compose.production.yml ps | grep -c 'Up')/$(docker-compose -f docker-compose.production.yml ps | wc -l) en cours d'exécution"
    echo "- CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
    echo "- Mémoire: $(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')%"
    echo "- Disque: $(df -h / | awk 'NR==2 {print $5}')"
    echo ""
    
    # Recommandations
    echo "💡 Recommandations:"
    
    # Vérifier l'espace disque
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 80 ]; then
        echo "- ⚠️ Nettoyez l'espace disque (actuellement ${disk_usage}%)"
    fi
    
    # Vérifier la mémoire
    mem_percent=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
    if (( $(echo "$mem_percent > 80" | bc -l) )); then
        echo "- ⚠️ Surveillez l'utilisation mémoire (actuellement ${mem_percent}%)"
    fi
    
    # Vérifier les erreurs
    error_count=$(docker-compose -f docker-compose.production.yml logs --since="24h" 2>&1 | grep -i "error\|exception\|failed" | wc -l)
    if [ "$error_count" -gt 10 ]; then
        echo "- ⚠️ Vérifiez les logs d'erreur (${error_count} erreurs récentes)"
    fi
}

# Fonction principale
main() {
    echo "🔍 Monitoring Gilbert - $(date)"
    echo "=================================="
    echo ""
    
    # Vérifications
    check_docker_services
    echo ""
    
    check_system_resources
    echo ""
    
    check_connectivity
    echo ""
    
    check_error_logs
    echo ""
    
    check_security
    echo ""
    
    show_summary
}

# Exécution
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [option]"
    echo ""
    echo "Options:"
    echo "  --help, -h     Afficher cette aide"
    echo "  --services     Vérifier uniquement les services Docker"
    echo "  --resources    Vérifier uniquement les ressources système"
    echo "  --connectivity Vérifier uniquement la connectivité"
    echo "  --logs         Vérifier uniquement les logs"
    echo "  --security     Vérifier uniquement la sécurité"
    echo ""
    echo "Sans option: Exécuter toutes les vérifications"
    exit 0
elif [ "$1" = "--services" ]; then
    check_docker_services
elif [ "$1" = "--resources" ]; then
    check_system_resources
elif [ "$1" = "--connectivity" ]; then
    check_connectivity
elif [ "$1" = "--logs" ]; then
    check_error_logs
elif [ "$1" = "--security" ]; then
    check_security
else
    main
fi 