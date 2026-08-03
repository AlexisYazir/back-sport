#!/bin/sh

# Iniciar FastAPI (ML) en segundo plano
cd /app/inference-service
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8001 &

# Iniciar NestJS (Backend)
cd /app
node dist/main