FROM node:20-alpine

# Instalar Python para FastAPI
RUN apk add --no-cache python3 py3-pip

WORKDIR /app

# ===== INSTALAR DEPENDENCIAS DE NESTJS =====
COPY package*.json ./
RUN npm ci --only=production

# ===== INSTALAR DEPENDENCIAS DE FASTAPI =====
COPY inference-service/requirements.txt ./inference-service/
RUN pip3 install --no-cache-dir -r ./inference-service/requirements.txt

# ===== COPIAR TODO EL CÓDIGO =====
COPY . .

# ===== COMPILAR NESTJS =====
RUN npm run build

# ===== HACER EJECUTABLE EL SCRIPT =====
RUN chmod +x start.sh

# ===== EXPONER PUERTOS =====
EXPOSE 3000 8001

# ===== INICIAR AMBOS SERVICIOS =====
CMD ["./start.sh"]