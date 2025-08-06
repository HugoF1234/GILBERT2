# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copier les fichiers de dépendances
COPY package*.json ./

# Installer les dépendances avec une approche plus robuste
RUN npm install --legacy-peer-deps --force

# Copier le code source
COPY . .

# Build de l'application avec les variables d'environnement
ARG VITE_API_URL=https://gilbert-assistant.ovh/api
ARG VITE_APP_NAME=Gilbert
ENV VITE_API_URL=${VITE_API_URL}
ENV VITE_APP_NAME=${VITE_APP_NAME}
RUN echo "Building with VITE_API_URL: $VITE_API_URL" && npm run build

# Production stage
FROM nginx:alpine

# Copier les fichiers buildés
COPY --from=builder /app/dist /usr/share/nginx/html

# Copier la configuration Nginx personnalisée
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Exposer le port 80
EXPOSE 80

# Démarrage de Nginx
CMD ["nginx", "-g", "daemon off;"] 