# 🚀 Démarrage Rapide - Gilbert sur VPS OVH

Ce guide vous permet de déployer Gilbert en **15 minutes** sur votre VPS OVH.

## ⚡ Déploiement Express

### 1. Connexion au VPS
```bash
ssh root@votre-ip-vps
```

### 2. Installation automatique
```bash
# Créer un utilisateur
adduser gilbert
usermod -aG sudo gilbert
su - gilbert

# Télécharger et exécuter l'installation
wget -O setup.sh https://raw.githubusercontent.com/HugoF1234/GILBERT/main/deployment/setup-vps.sh
chmod +x setup.sh
./setup.sh
```

### 3. Configuration rapide
```bash
cd ~/gilbert

# Copier les fichiers de déploiement
cp -r deployment/* .

# Configurer l'environnement
cp env.example .env
nano .env
```

### 4. Variables minimales à configurer
```bash
# Dans le fichier .env, modifiez au minimum :
DOMAIN_NAME=gilbert-assistant.ovh
SSL_EMAIL=hugofouan@gmail.com
POSTGRES_PASSWORD=gilbertmdp2025
JWT_SECRET=GilbertJWT2025!SuperSecretKey32Chars
ASSEMBLYAI_API_KEY=3419005ee6924e08a14235043cabcd4e
```

### 5. Déploiement
```bash
chmod +x deploy.sh
./deploy.sh
```

## ✅ Vérification

Après le déploiement, vérifiez que tout fonctionne :

```bash
# Vérifier les services
./monitor.sh

# Voir les logs
docker-compose -f docker-compose.production.yml logs -f

# Tester l'API
curl https://gilbert-assistant.ovh/api/health
```

## 🌐 Accès à l'application

- **Application** : https://gilbert-assistant.ovh
- **API Documentation** : https://gilbert-assistant.ovh/api/docs
- **Compte admin** : admin@gilbert.com / admin123

## 🔧 Commandes utiles

```bash
# Monitoring
./monitor.sh

# Logs en temps réel
docker-compose -f docker-compose.production.yml logs -f

# Redémarrer
docker-compose -f docker-compose.production.yml restart

# Arrêter
docker-compose -f docker-compose.production.yml down

# Mettre à jour
git pull && ./deploy.sh
```

## 🚨 En cas de problème

1. **Vérifiez les logs** : `docker-compose -f docker-compose.production.yml logs -f`
2. **Vérifiez le monitoring** : `./monitor.sh`
3. **Redémarrez les services** : `docker-compose -f docker-compose.production.yml restart`

## 📞 Support

- **Documentation complète** : `deployment/README.md`
- **Scripts de monitoring** : `./monitor.sh --help`
- **Logs détaillés** : Voir les fichiers dans `deployment/`

---

**🎉 Votre application Gilbert est maintenant en ligne !** 