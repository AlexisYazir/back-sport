#!/bin/sh

echo "=== INICIANDO SERVICIOS ==="

# Verificar que exista el build
if [ -f /app/dist/src/main.js ]; then
    echo "✅ NestJS build encontrado en /app/dist/src/main.js"
else
    echo "❌ ERROR: No se encuentra /app/dist/src/main.js"
    echo "📂 Contenido de /app/dist:"
    ls -la /app/dist/ || echo "❌ Carpeta dist no existe"
    echo "📂 Contenido de /app/dist/src:"
    ls -la /app/dist/src/ 2>/dev/null || echo "❌ Carpeta dist/src no existe"
    exit 1
fi

# Iniciar FastAPI (ML) en segundo plano
echo "🚀 Iniciando FastAPI en puerto 8001..."
cd /app/inference-service
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8001 &

# Esperar a que FastAPI esté listo
echo "⏳ Esperando a que FastAPI esté listo..."
sleep 5

# Verificar que FastAPI esté corriendo
if curl -s http://localhost:8001/health > /dev/null; then
    echo "✅ FastAPI corriendo en http://localhost:8001"
else
    echo "⚠️  FastAPI no responde en http://localhost:8001, pero continuamos..."
fi

# Iniciar NestJS (Backend)
echo "🚀 Iniciando NestJS en puerto 3000..."
cd /app
node dist/src/main.js