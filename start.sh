#!/bin/sh

echo "=== INICIANDO SERVICIOS ==="

# Iniciar FastAPI (ML) en segundo plano
echo "🚀 Iniciando FastAPI (ML) en puerto 8001..."
cd /app/inference-service
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8001 &

# Esperar a que FastAPI esté listo
echo "⏳ Esperando a que FastAPI esté listo..."
sleep 10

# Verificar que FastAPI está corriendo
if curl -s http://localhost:8001/health > /dev/null 2>&1; then
    echo "✅ FastAPI corriendo en http://localhost:8001"
else
    echo "❌ ERROR: FastAPI no responde en http://localhost:8001"
    echo "📄 Revisa los logs de FastAPI arriba para ver el error"
fi

# Iniciar NestJS (Backend)
echo "🚀 Iniciando NestJS en puerto 3000..."
cd /app
node dist/src/main.js