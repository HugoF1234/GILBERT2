#!/bin/bash

# Script d'installation automatique pour VPS OVH
# Gilbert - Meeting Transcriber

set -e

echo "🚀 Installation de Gilbert sur VPS OVH"
echo "======================================"

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

# Vérifier si on est root
if [[ $EUID -eq 0 ]]; then
   log_error "Ce script ne doit pas être exécuté en tant que root"
   exit 1
fi

# Vérifier la version d'Ubuntu
if ! grep -q "Ubuntu 22.04" /etc/os-release; then
    log_warn "Ce script est optimisé pour Ubuntu 22.04"
fi

# Mise à jour du système
log_info "Mise à jour du système..."
sudo apt update && sudo apt upgrade -y

# Installation des dépendances système
log_info "Installation des dépendances système..."
sudo apt install -y \
    curl \
    wget \
    git \
    unzip \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    ufw \
    fail2ban \
    htop \
    nginx \
    certbot \
    python3-certbot-nginx

# Installation de Docker
log_info "Installation de Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Ajouter l'utilisateur au groupe docker
sudo usermod -aG docker $USER

# Installation de Docker Compose
log_info "Installation de Docker Compose..."
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Configuration du firewall
log_info "Configuration du firewall..."
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp

# Configuration de fail2ban
log_info "Configuration de fail2ban..."
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Création de la structure de répertoires
log_info "Création de la structure de répertoires..."
mkdir -p ~/gilbert
cd ~/gilbert

# Cloner le projet (si pas déjà fait)
if [ ! -d "backend" ]; then
    log_info "Clonage du projet..."
    # TODO: Remplacer par votre URL de repository GitHub
    git clone https://github.com/HugoF1234/GILBERT.git .
fi

# Création des répertoires pour les certificats SSL
mkdir -p certbot/conf
mkdir -p certbot/www

# Configuration des permissions
sudo chown -R $USER:$USER ~/gilbert

log_info "Installation terminée !"
echo ""
echo "📋 Prochaines étapes :"
echo "1. Configurez votre domaine DNS pour pointer vers ce serveur"
echo "2. Copiez le fichier .env.example vers .env et configurez les variables"
echo "3. Lancez le déploiement avec : ./deploy.sh"
echo ""
echo "🔧 Commandes utiles :"
echo "- Vérifier les services : docker-compose ps"
echo "- Voir les logs : docker-compose logs -f"
echo "- Redémarrer : docker-compose restart"
echo "- Arrêter : docker-compose down" 