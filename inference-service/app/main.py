from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sklearn.metrics.pairwise import cosine_similarity


APP_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = APP_DIR / "models"
DEMAND_MODEL_PATH = MODELS_DIR / "demand_forecasting_pipeline.joblib"
RECOMMENDER_MODEL_PATH = MODELS_DIR / "content_recommender.joblib"

app = FastAPI(title="Sport Center ML Inference", version="1.0.0")

# ===== CORS PARA PRODUCCIÓN =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

demand_artifact: dict[str, Any] | None = None
recommender_artifact: dict[str, Any] | None = None


class DemandRequest(BaseModel):
    id_variante: int = Field(gt=0)
    cantidad_hace_3_meses: float = Field(ge=0)
    cantidad_hace_2_meses: float = Field(ge=0)
    cantidad_mes_anterior: float = Field(ge=0)
    mes_objetivo: str | None = None
    mes_num: float | None = None
    mes_sin: float | None = None
    mes_cos: float | None = None
    q1: float | None = None
    q2: float | None = None
    q3: float | None = None
    q4: float | None = None
    lag_mean: float | None = None
    lag_weighted: float | None = None
    lag_trend: float | None = None
    lag_last_delta: float | None = None
    lag_volatility: float | None = None
    lag_min: float | None = None
    lag_max: float | None = None
    zero_lags: float | None = None


class ProductFeatures(BaseModel):
    id_producto: int = Field(gt=0)
    nombre_producto: str = ""
    descripcion: str = ""
    categoria: str = ""
    categoria_padre: str = ""
    marca: str = ""
    deportes: list[str] = Field(default_factory=list)
    atributos: str | dict[str, Any] = ""
    precio_promedio: float = Field(default=0, ge=0)


class RecommendationRequest(BaseModel):
    product: ProductFeatures
    limit: int = Field(default=10, ge=1, le=20)


class RecommendByIdRequest(BaseModel):
    product_id: int = Field(gt=0)
    limit: int = Field(default=10, ge=1, le=20)


def load_joblib(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"No existe el artefacto {label}: {path}")
    artifact = joblib.load(path)
    if not isinstance(artifact, dict):
        raise RuntimeError(f"El artefacto {label} no tiene formato valido.")
    return artifact


@app.on_event("startup")
def startup() -> None:
    global demand_artifact, recommender_artifact
    demand_artifact = load_joblib(DEMAND_MODEL_PATH, "demand")
    recommender_artifact = load_joblib(RECOMMENDER_MODEL_PATH, "recommendation")
    required_recommender_keys = {"preprocessor", "matrix", "product_ids", "feature_columns"}
    missing = required_recommender_keys - set(recommender_artifact)
    if missing:
        raise RuntimeError(f"Artefacto de recomendacion incompleto: {sorted(missing)}")
    if "pipeline" not in demand_artifact or "feature_columns" not in demand_artifact:
        raise RuntimeError("Artefacto de demanda incompleto.")


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok" if demand_artifact and recommender_artifact else "degraded",
        "models": {
            "demand": bool(demand_artifact),
            "recommendation": bool(recommender_artifact),
        },
    }


def parse_target_month(value: str | None) -> datetime:
    if value:
        clean = str(value).strip()
        candidates = [clean, clean[:10], f"{clean[:7]}-01"]
        for candidate in candidates:
            try:
                return datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            except ValueError:
                continue
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, 1)


def enrich_demand_row(row: dict[str, Any]) -> dict[str, Any]:
    month = parse_target_month(row.get("mes_objetivo")).month
    l3 = float(row.get("cantidad_hace_3_meses") or 0)
    l2 = float(row.get("cantidad_hace_2_meses") or 0)
    l1 = float(row.get("cantidad_mes_anterior") or 0)
    lags = np.array([l3, l2, l1], dtype=float)

    if row.get("mes_num") is not None:
        return row

    row["mes_num"] = month
    row["mes_sin"] = math.sin(2 * math.pi * month / 12)
    row["mes_cos"] = math.cos(2 * math.pi * month / 12)
    row["q1"] = 1 if 1 <= month <= 3 else 0
    row["q2"] = 1 if 4 <= month <= 6 else 0
    row["q3"] = 1 if 7 <= month <= 9 else 0
    row["q4"] = 1 if 10 <= month <= 12 else 0
    row["lag_mean"] = float(lags.mean())
    row["lag_weighted"] = l3 * 0.2 + l2 * 0.3 + l1 * 0.5
    row["lag_trend"] = l1 - l3
    row["lag_last_delta"] = l1 - l2
    row["lag_volatility"] = float(lags.std(ddof=1)) if len(lags) > 1 else 0.0
    row["lag_min"] = float(lags.min())
    row["lag_max"] = float(lags.max())
    row["zero_lags"] = int(np.sum(lags == 0))
    return row


@app.post("/v1/demand/predict")
def predict_demand(payload: DemandRequest) -> dict[str, Any]:
    if demand_artifact is None:
        raise HTTPException(status_code=503, detail="Modelo de demanda no cargado.")
    feature_columns = demand_artifact["feature_columns"]
    row = enrich_demand_row(payload.model_dump())
    frame = pd.DataFrame([row])
    try:
        prediction = float(demand_artifact["pipeline"].predict(frame[feature_columns])[0])
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"No fue posible predecir: {exc}") from exc
    if not math.isfinite(prediction):
        prediction = 0
    prediction = max(0.0, prediction)
    return {
        "id_variante": payload.id_variante,
        "predicted_units": round(prediction, 2),
        "model_version": demand_artifact.get("version"),
        "algorithm": demand_artifact.get("algorithm"),
    }


def normalize_product(product: ProductFeatures) -> dict[str, Any]:
    atributos = product.atributos
    if isinstance(atributos, dict):
        atributos = " ".join(f"{key} {value}" for key, value in sorted(atributos.items()))
    deportes = "|".join(product.deportes or [])
    return {
        "id_producto": product.id_producto,
        "nombre_producto": product.nombre_producto or "",
        "descripcion": product.descripcion or "",
        "categoria": product.categoria or "",
        "categoria_padre": product.categoria_padre or "",
        "marca": product.marca or "",
        "deportes": deportes or "Sin deporte",
        "atributos": str(atributos or ""),
        "precio_promedio": float(product.precio_promedio or 0),
        "contenido_tfidf": " ".join(
            [
                product.nombre_producto or "",
                product.descripcion or "",
                product.categoria or "",
                product.categoria_padre or "",
                product.marca or "",
                deportes,
                str(atributos or ""),
            ]
        ).lower(),
    }


@app.post("/v1/products/recommend")
def recommend_products(payload: RecommendationRequest) -> dict[str, Any]:
    if recommender_artifact is None:
        raise HTTPException(status_code=503, detail="Modelo de recomendacion no cargado.")
    feature_columns = recommender_artifact["feature_columns"]
    product_ids = [int(value) for value in recommender_artifact["product_ids"]]
    matrix = recommender_artifact["matrix"]
    row = normalize_product(payload.product)
    frame = pd.DataFrame([row])
    try:
        vector = recommender_artifact["preprocessor"].transform(frame[feature_columns])
        scores = cosine_similarity(vector, matrix)[0]
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"No fue posible recomendar: {exc}") from exc

    ranked: list[dict[str, Any]] = []
    for index in np.argsort(scores)[::-1]:
        candidate_id = product_ids[int(index)]
        if candidate_id == payload.product.id_producto:
            continue
        ranked.append(
            {
                "id_producto": candidate_id,
                "score": round(float(scores[int(index)]), 6),
            }
        )
        if len(ranked) >= payload.limit:
            break
    return {
        "product_id": payload.product.id_producto,
        "model_version": recommender_artifact.get("version"),
        "algorithm": recommender_artifact.get("algorithm"),
        "recommendations": ranked,
    }


@app.post("/v1/products/recommend-by-id")
def recommend_by_id(payload: RecommendByIdRequest) -> dict[str, Any]:
    if recommender_artifact is None:
        raise HTTPException(status_code=503, detail="Modelo de recomendacion no cargado.")
    
    product_ids = [int(value) for value in recommender_artifact["product_ids"]]
    matrix = recommender_artifact["matrix"]
    
    product_index = None
    for idx, pid in enumerate(product_ids):
        if int(pid) == payload.product_id:
            product_index = idx
            break
    
    if product_index is None:
        raise HTTPException(
            status_code=404, 
            detail=f"Producto {payload.product_id} no encontrado en el modelo."
        )
    
    try:
        vector = matrix[product_index:product_index + 1]
        scores = cosine_similarity(vector, matrix)[0]
    except Exception as exc:
        raise HTTPException(
            status_code=400, 
            detail=f"No fue posible calcular recomendaciones: {exc}"
        ) from exc

    ranked: list[dict[str, Any]] = []
    for idx in np.argsort(scores)[::-1]:
        candidate_id = product_ids[idx]
        if candidate_id == payload.product_id:
            continue
        ranked.append(
            {
                "id_producto": candidate_id,
                "score": round(float(scores[idx]), 6),
            }
        )
        if len(ranked) >= payload.limit:
            break
    
    return {
        "product_id": payload.product_id,
        "model_version": recommender_artifact.get("version"),
        "algorithm": recommender_artifact.get("algorithm"),
        "recommendations": ranked,
    }