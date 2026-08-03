FROM node:20-alpine

# ===== INSTALAR PYTHON Y DEPENDENCIAS DE COMPILACIÓN =====
RUN apk add --no-cache \
    python3 \
    py3-pip \
    gcc \
    g++ \
    musl-dev \
    python3-dev \
    libffi-dev \
    openblas-dev \
    lapack-dev \
    gfortran \
    build-base

WORKDIR /app

# ===== INSTALAR DEPENDENCIAS DE NESTJS (INCLUYENDO DEV PARA COMPILAR) =====
COPY package*.json ./
RUN npm ci

# ===== INSTALAR DEPENDENCIAS DE FASTAPI =====
COPY inference-service/requirements.txt ./inference-service/
RUN pip3 install --no-cache-dir --break-system-packages --no-build-isolation numpy==2.4.4
RUN pip3 install --no-cache-dir --break-system-packages -r ./inference-service/requirements.txt

# ===== COPIAR TODO EL CÓDIGO =====
COPY . .

# ===== COMPILAR NESTJS =====
RUN npm run build

# ===== VERIFICAR QUE EL BUILD EXISTE =====
RUN ls -la /app/dist/
RUN ls -la /app/dist/src/ || echo "❌ dist/src no existe"

# ===== LIMPIAR DEPENDENCIAS DE DESARROLLO PARA PRODUCCIÓN =====
RUN npm prune --production

# ===== HACER EJECUTABLE EL SCRIPT =====
RUN chmod +x start.sh

# ===== EXPONER PUERTOS =====
EXPOSE 3000 8001

# ===== INICIAR AMBOS SERVICIOS =====
CMD ["./start.sh"]