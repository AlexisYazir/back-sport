FROM node:20-alpine

WORKDIR /app

# Instalar dependencias
COPY package*.json ./
RUN npm ci --only=production

# Copiar código y compilar
COPY . .
RUN npm run build

# Limpiar dependencias de desarrollo
RUN npm prune --production

# Exponer puerto
EXPOSE 3000

# Iniciar NestJS
CMD ["node", "dist/src/main.js"]