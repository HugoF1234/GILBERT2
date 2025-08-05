# 🚀 Guide de Déploiement Gilbert sur VPS OVH

Ce guide vous accompagne pour déployer Gilbert (Meeting Transcriber) sur votre VPS OVH avec une architecture robuste et scalable.

## 📋 Prérequis

- **VPS OVH** : 2 vCores, 4GB RAM, 80GB SSD (Ubuntu 22.04 LTS)
- **Domaine** : Un nom de domaine configuré
- **API Keys** : AssemblyAI et Mistral AI

## 🏗️ Architecture de Déploiement

```
VPS OVH (2 vCores, 4GB RAM, 80GB SSD)
├── Nginx (Reverse Proxy + SSL)
├── Docker Compose
│   ├── Backend API (FastAPI)
│   ├── PostgreSQL (Base de données)
│   ├── Redis (Cache)
│   └── Frontend (React)
├── Certbot (SSL automatique)
└── Monitoring (Firewall + Fail2ban)
```

## 🚀 Étapes de Déploiement

### 1. Connexion au VPS

```bash
ssh root@votre-ip-vps
```

### 2. Création d'un utilisateur non-root

```bash
# Créer un utilisateur
adduser gilbert
usermod -aG sudo gilbert

# Basculer vers l'utilisateur
su - gilbert
```

### 3. Installation automatique

```bash
# Télécharger le script d'installation
wget https://raw.githubusercontent.com/HugoF1234/GILBERT/main/deployment/setup-vps.sh
chmod +x setup-vps.sh
./setup-vps.sh
```

### 4. Configuration du projet

```bash
cd ~/gilbert

# Copier les fichiers de déploiement
cp -r deployment/* .

# Configurer les variables d'environnement
cp env.example .env
nano .env
```

### 5. Configuration du fichier .env

```bash
# Variables critiques à configurer
DOMAIN_NAME=votre-domaine.com
SSL_EMAIL=votre-email@domaine.com
POSTGRES_PASSWORD=mot_de_passe_super_securise
JWT_SECRET=jwt_secret_super_securise_et_long
ASSEMBLYAI_API_KEY=votre_cle_api_assemblyai
MISTRAL_API_KEY=votre_cle_api_mistral
```

### 6. Configuration DNS

Configurez votre domaine pour pointer vers l'IP de votre VPS :
- **A Record** : `@` → `51.38.177.18`
- **A Record** : `www` → `51.38.177.18`

### 7. Déploiement

```bash
# Lancer le déploiement
chmod +x deploy.sh
./deploy.sh
```

## 🔧 Configuration Avancée

### Monitoring et Logs

```bash
# Voir les logs en temps réel
docker-compose -f docker-compose.production.yml logs -f

# Vérifier l'état des services
docker-compose -f docker-compose.production.yml ps

# Monitoring des ressources
htop
```

### Sauvegarde

```bash
# Sauvegarde de la base de données
docker-compose -f docker-compose.production.yml exec postgres pg_dump -U gilbert_user gilbert_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Sauvegarde des uploads
tar -czf uploads_backup_$(date +%Y%m%d_%H%M%S).tar.gz backend/uploads/
```

### Mise à jour

```bash
# Mettre à jour le code
git pull origin main

# Redéployer
./deploy.sh
```

## 🔒 Sécurité

### Firewall (UFW)

```bash
# Vérifier le statut
sudo ufw status

# Ajouter des règles personnalisées
sudo ufw allow from votre-ip-personnelle to any port 22
```

### Fail2ban

```bash
# Vérifier le statut
sudo fail2ban-client status

# Voir les logs
sudo tail -f /var/log/fail2ban.log
```

### SSL/TLS

```bash
# Renouveler le certificat SSL
docker-compose -f docker-compose.production.yml run --rm certbot renew

# Vérifier la validité
openssl x509 -in certbot/conf/live/votre-domaine.com/fullchain.pem -text -noout
```

## 📊 Performance et Optimisation

### Optimisations Nginx

- **Gzip** : Compression automatique activée
- **Cache** : Cache des assets statiques (1 an)
- **SSL** : Configuration optimisée avec HTTP/2

### Optimisations PostgreSQL

- **Pool de connexions** : 10 connexions max
- **Index** : Index automatiques sur les clés étrangères
- **Maintenance** : VACUUM automatique

### Optimisations Redis

- **Mémoire** : Limite à 256MB
- **Politique** : LRU pour l'éviction
- **Persistence** : AOF activé

## 🚨 Dépannage

### Problèmes courants

1. **Service ne démarre pas**
   ```bash
   docker-compose -f docker-compose.production.yml logs service_name
   ```

2. **Certificat SSL expiré**
   ```bash
   docker-compose -f docker-compose.production.yml run --rm certbot renew
   ```

3. **Base de données inaccessible**
   ```bash
   docker-compose -f docker-compose.production.yml exec postgres psql -U gilbert_user -d gilbert_db
   ```

4. **Mémoire insuffisante**
   ```bash
   # Vérifier l'utilisation
   free -h
   
   # Nettoyer Docker
   docker system prune -a
   ```

### Logs utiles

```bash
# Logs Nginx
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# Logs Docker
docker-compose -f docker-compose.production.yml logs -f

# Logs système
sudo journalctl -f
```

## 📈 Monitoring Recommandé

### Outils de monitoring

1. **Prometheus + Grafana** (optionnel)
2. **Netdata** (monitoring système)
3. **Logwatch** (rapports de logs)

### Métriques importantes

- **CPU** : < 80% en moyenne
- **RAM** : < 3GB utilisés
- **Disque** : < 70% utilisé
- **Connexions** : < 1000 simultanées

## 🔄 Maintenance

### Tâches quotidiennes

- Vérification des logs d'erreur
- Monitoring de l'espace disque
- Vérification des sauvegardes

### Tâches hebdomadaires

- Mise à jour des packages système
- Nettoyage des logs anciens
- Vérification de la sécurité

### Tâches mensuelles

- Renouvellement des certificats SSL
- Analyse des performances
- Mise à jour de l'application

## 📞 Support

En cas de problème :

1. Vérifiez les logs : `docker-compose -f docker-compose.production.yml logs -f`
2. Consultez ce guide de dépannage
3. Vérifiez la documentation de l'API : `https://votre-domaine.com/api/docs`

---

**🎉 Félicitations !** Votre application Gilbert est maintenant déployée et prête à être utilisée en production. 