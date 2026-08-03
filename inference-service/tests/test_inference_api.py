from __future__ import annotations

import importlib
from pathlib import Path

from fastapi.testclient import TestClient


def test_health_endpoint_reports_loaded_models():
    main = importlib.import_module("app.main")

    with TestClient(main.app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] in {"ok", "degraded"}
    assert "demand" in payload["models"]
    assert "recommendation" in payload["models"]


def test_demand_prediction_contract():
    main = importlib.import_module("app.main")

    with TestClient(main.app) as client:
        response = client.post(
            "/v1/demand/predict",
            json={
                "id_variante": 1,
                "cantidad_hace_3_meses": 2,
                "cantidad_hace_2_meses": 3,
                "cantidad_mes_anterior": 4,
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["id_variante"] == 1
    assert payload["predicted_units"] >= 0


def test_recommendation_contract():
    main = importlib.import_module("app.main")

    with TestClient(main.app) as client:
        response = client.post(
            "/v1/products/recommend",
            json={
                "product": {
                    "id_producto": 1,
                    "nombre_producto": "Producto de prueba",
                    "descripcion": "Producto deportivo para entrenamiento",
                    "categoria": "Playeras",
                    "categoria_padre": "Ropa",
                    "marca": "Nike",
                    "deportes": ["Futbol"],
                    "atributos": "Genero: Unisex | Color: Azul",
                    "precio_promedio": 300,
                },
                "limit": 5,
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["product_id"] == 1
    assert isinstance(payload["recommendations"], list)
    assert len(payload["recommendations"]) <= 5


def test_demand_prediction_accepts_variant_without_history():
    main = importlib.import_module("app.main")

    with TestClient(main.app) as client:
        response = client.post(
            "/v1/demand/predict",
            json={
                "id_variante": 999999,
                "cantidad_hace_3_meses": 0,
                "cantidad_hace_2_meses": 0,
                "cantidad_mes_anterior": 0,
            },
        )

    assert response.status_code == 200
    assert response.json()["predicted_units"] >= 0


def test_recommendation_accepts_new_product_as_query():
    main = importlib.import_module("app.main")

    with TestClient(main.app) as client:
        response = client.post(
            "/v1/products/recommend",
            json={
                "product": {
                    "id_producto": 999999,
                    "nombre_producto": "Producto nuevo no entrenado",
                    "descripcion": "Equipo para futbol y entrenamiento",
                    "categoria": "Gorras",
                    "categoria_padre": "Accesorios",
                    "marca": "Marca nueva",
                    "deportes": ["Futbol"],
                    "atributos": {"Genero": "Unisex", "Color": "Negro"},
                    "precio_promedio": 250,
                },
                "limit": 10,
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["product_id"] == 999999
    assert isinstance(payload["recommendations"], list)


def test_invalid_identifier_is_rejected():
    main = importlib.import_module("app.main")

    with TestClient(main.app) as client:
        response = client.post(
            "/v1/demand/predict",
            json={
                "id_variante": 0,
                "cantidad_hace_3_meses": 0,
                "cantidad_hace_2_meses": 0,
                "cantidad_mes_anterior": 0,
            },
        )

    assert response.status_code == 422


def test_missing_artifact_raises_clear_error(tmp_path):
    main = importlib.import_module("app.main")

    missing_path = Path(tmp_path) / "missing.joblib"
    try:
        main.load_joblib(missing_path, "missing")
    except RuntimeError as exc:
        assert "No existe el artefacto" in str(exc)
    else:
        raise AssertionError("load_joblib debio fallar con un artefacto ausente")
