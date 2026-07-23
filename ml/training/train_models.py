from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.cluster import KMeans
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    davies_bouldin_score,
    mean_absolute_error,
    mean_squared_error,
    r2_score,
    silhouette_score,
)
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler

os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")

PIPELINES = {"demand", "recommendation", "clustering"}
STOPWORDS_ES = [
    "de", "la", "el", "en", "y", "para", "con", "un", "una", "los", "las",
    "del", "al", "por", "es", "color", "marca",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Entrena los modelos de Sport Center.")
    parser.add_argument("--datasets-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--models-dir", required=True)
    parser.add_argument(
        "--pipelines",
        default="demand,recommendation,clustering",
        help="Lista separada por comas.",
    )
    return parser.parse_args()


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    shutil.copy2(source, temporary)
    os.replace(temporary, destination)


def train_demand(dataset: Path, work: Path) -> dict:
    data = pd.read_csv(dataset, parse_dates=["mes_objetivo"])
    features = [
        "cantidad_hace_3_meses",
        "cantidad_hace_2_meses",
        "cantidad_mes_anterior",
    ]
    target = "cantidad_mes_objetivo"
    if len(data) < 20 or data["mes_objetivo"].nunique() < 7:
        raise ValueError("El dataset de demanda no tiene historial mensual suficiente.")

    model = HistGradientBoostingRegressor(
        max_iter=300,
        learning_rate=0.05,
        max_leaf_nodes=20,
        l2_regularization=0.1,
        random_state=42,
    )
    months = np.array(sorted(data["mes_objetivo"].unique()))
    cutoff = pd.Timestamp(months[-min(6, max(1, len(months) // 4))])
    train = data[data["mes_objetivo"] < cutoff]
    test = data[data["mes_objetivo"] >= cutoff]
    evaluation_model = clone(model).fit(train[features], train[target])
    evaluation_predictions = np.clip(evaluation_model.predict(test[features]), 0, None)

    metrics = {
        "r2": round(float(r2_score(test[target], evaluation_predictions)), 6),
        "mae": round(float(mean_absolute_error(test[target], evaluation_predictions)), 6),
        "rmse": round(
            float(np.sqrt(mean_squared_error(test[target], evaluation_predictions))),
            6,
        ),
        "train_rows": int(len(train)),
        "test_rows": int(len(test)),
    }

    final_model = clone(model).fit(data[features], data[target])
    latest = (
        data.sort_values("mes_objetivo")
        .groupby("id_variante", as_index=False)
        .tail(1)
        .copy()
    )
    next_features = pd.DataFrame(
        {
            "cantidad_hace_3_meses": latest["cantidad_hace_2_meses"],
            "cantidad_hace_2_meses": latest["cantidad_mes_anterior"],
            "cantidad_mes_anterior": latest["cantidad_mes_objetivo"],
        }
    )
    predictions = np.rint(
        np.clip(final_model.predict(next_features), 0, None)
    ).astype(int)
    projected_month = (
        latest["mes_objetivo"].max().to_period("M") + 1
    ).to_timestamp()

    result = latest[
        [
            "id_producto",
            "id_variante",
            "nombre_producto",
            "mes_objetivo",
            "cantidad_hace_3_meses",
            "cantidad_hace_2_meses",
            "cantidad_mes_anterior",
            "cantidad_mes_objetivo",
        ]
    ].copy()
    result.insert(4, "mes_proyectado", projected_month.strftime("%Y-%m-%d"))
    result["demanda_estimada"] = predictions
    result["variacion_estimada"] = (
        result["demanda_estimada"] - result["cantidad_mes_objetivo"]
    )
    tolerance = np.maximum(1, np.rint(result["cantidad_mes_objetivo"] * 0.05))
    result["tendencia"] = np.where(
        result["variacion_estimada"] > tolerance,
        "creciente",
        np.where(
            result["variacion_estimada"] < -tolerance,
            "decreciente",
            "estable",
        ),
    )

    result_file = work / "01_resultados_prediccion_demanda.csv"
    model_file = work / "demand_model.joblib"
    result.to_csv(result_file, index=False, encoding="utf-8")
    joblib.dump(
        {
            "model": final_model,
            "features": features,
            "target": target,
            "metrics": metrics,
            "trained_at": pd.Timestamp.now("UTC").isoformat(),
        },
        model_file,
    )
    return {
        "rows": int(len(data)),
        "result_rows": int(len(result)),
        "metrics": metrics,
        "files": [result_file.name, model_file.name],
    }


def sports_sets(values: pd.Series) -> list[set[str]]:
    return [
        {
            item.strip().lower()
            for item in str(value).split("|")
            if item.strip() and item.strip().lower() != "sin deporte"
        }
        for value in values
    ]


def train_recommendations(dataset: Path, work: Path) -> dict:
    products = pd.read_csv(dataset)
    if len(products) < 2:
        raise ValueError("Se requieren al menos dos productos disponibles.")

    vectorizer = TfidfVectorizer(
        stop_words=STOPWORDS_ES,
        ngram_range=(1, 2),
        min_df=1,
        sublinear_tf=True,
    )
    tfidf = vectorizer.fit_transform(products["contenido_tfidf"].fillna(""))
    text_similarity = cosine_similarity(tfidf)
    sports = sports_sets(products["deportes"])
    total = len(products)
    sport_similarity = np.zeros((total, total))
    for left in range(total):
        for right in range(total):
            union = sports[left] | sports[right]
            sport_similarity[left, right] = (
                len(sports[left] & sports[right]) / len(union) if union else 0
            )

    categories = products["categoria"].astype(str).to_numpy()
    brands = products["marca"].astype(str).to_numpy()
    prices = products["precio_promedio"].astype(float).to_numpy()
    category_similarity = (categories[:, None] == categories[None, :]).astype(float)
    brand_similarity = (brands[:, None] == brands[None, :]).astype(float)
    reference = np.maximum(prices[:, None], prices[None, :])
    price_similarity = np.clip(
        1 - np.abs(prices[:, None] - prices[None, :]) / np.maximum(reference, 1),
        0,
        1,
    )
    final_similarity = (
        0.45 * text_similarity
        + 0.20 * sport_similarity
        + 0.15 * category_similarity
        + 0.10 * brand_similarity
        + 0.10 * price_similarity
    )
    np.fill_diagonal(final_similarity, -1)

    rows = []
    top_n = min(8, total - 1)
    product_ids = products["id_producto"].astype(int).to_numpy()
    for index, product_id in enumerate(product_ids):
        recommended = np.argsort(final_similarity[index])[::-1][:top_n]
        for rank, candidate_index in enumerate(recommended, start=1):
            rows.append(
                {
                    "id_producto_origen": int(product_id),
                    "id_producto_recomendado": int(product_ids[candidate_index]),
                    "posicion": rank,
                    "similitud": round(
                        float(final_similarity[index, candidate_index]), 6
                    ),
                }
            )

    result = pd.DataFrame(rows)
    result_file = work / "02_resultados_recomendacion_productos.csv"
    model_file = work / "recommendation_model.joblib"
    result.to_csv(result_file, index=False, encoding="utf-8")
    joblib.dump(
        {
            "vectorizer": vectorizer,
            "tfidf_matrix": tfidf,
            "similarity_matrix": final_similarity,
            "product_ids": product_ids,
            "trained_at": pd.Timestamp.now("UTC").isoformat(),
        },
        model_file,
    )
    top_scores = result.groupby("id_producto_origen")["similitud"].head(5)
    metrics = {
        "catalog_coverage_percent": 100.0,
        "average_top_5_score": round(float(top_scores.mean()), 6),
    }
    return {
        "rows": int(total),
        "result_rows": int(len(result)),
        "metrics": metrics,
        "files": [result_file.name, model_file.name],
    }


def segment_names(summary: pd.DataFrame) -> tuple[dict[int, str], dict[str, str]]:
    profile = summary.copy()
    profile["value"] = (
        profile["frecuencia_promedio"].rank(pct=True)
        + profile["gasto_promedio"].rank(pct=True)
        - profile["recencia_promedio"].rank(pct=True)
    )
    pending = set(int(index) for index in profile.index)
    high_value = int(profile["value"].idxmax())
    pending.remove(high_value)
    at_risk = int(profile.loc[list(pending), "recencia_promedio"].idxmax())
    pending.remove(at_risk)
    occasional = int(
        (
            profile.loc[list(pending), "frecuencia_promedio"].rank()
            + profile.loc[list(pending), "gasto_promedio"].rank()
        ).idxmin()
    )
    pending.remove(occasional)
    potential = pending.pop()
    names = {
        high_value: "Clientes de alto valor",
        potential: "Clientes con potencial",
        occasional: "Clientes ocasionales",
        at_risk: "Clientes en riesgo",
    }
    actions = {
        "Clientes de alto valor": "Beneficios exclusivos y comunicacion de novedades.",
        "Clientes con potencial": "Promociones para aumentar frecuencia y ticket.",
        "Clientes ocasionales": "Recordatorios y ofertas sencillas de reactivacion.",
        "Clientes en riesgo": "Campana de recuperacion y seguimiento personalizado.",
    }
    return names, actions


def train_clustering(dataset: Path, work: Path) -> dict:
    customers = pd.read_csv(dataset)
    variables = ["recencia_dias", "frecuencia_12_meses", "gasto_12_meses"]
    if len(customers) < 20:
        raise ValueError("Se requieren al menos 20 clientes para segmentar.")

    transformed = np.log1p(customers[variables])
    scaler = StandardScaler()
    scaled = scaler.fit_transform(transformed)
    clusters = min(4, len(customers) - 1)
    model = KMeans(
        n_clusters=clusters,
        init="k-means++",
        n_init=30,
        max_iter=300,
        random_state=42,
    )
    result = customers.copy()
    result["cluster"] = model.fit_predict(scaled)
    summary = result.groupby("cluster").agg(
        recencia_promedio=("recencia_dias", "mean"),
        frecuencia_promedio=("frecuencia_12_meses", "mean"),
        gasto_promedio=("gasto_12_meses", "mean"),
    )
    names, actions = segment_names(summary)
    result["segmento"] = result["cluster"].map(names)
    result["accion_sugerida"] = result["segmento"].map(actions)

    metrics = {
        "silhouette": round(float(silhouette_score(scaled, result["cluster"])), 6),
        "davies_bouldin": round(
            float(davies_bouldin_score(scaled, result["cluster"])), 6
        ),
        "clusters": int(clusters),
    }
    result_file = work / "03_resultados_segmentacion_clientes.csv"
    model_file = work / "clustering_model.joblib"
    result.to_csv(result_file, index=False, encoding="utf-8")
    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "variables": variables,
            "names": names,
            "actions": actions,
            "metrics": metrics,
            "trained_at": pd.Timestamp.now("UTC").isoformat(),
        },
        model_file,
    )
    return {
        "rows": int(len(customers)),
        "result_rows": int(len(result)),
        "metrics": metrics,
        "files": [result_file.name, model_file.name],
    }


def main() -> int:
    args = parse_args()
    datasets_dir = Path(args.datasets_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    models_dir = Path(args.models_dir).resolve()
    selected = {item.strip() for item in args.pipelines.split(",") if item.strip()}
    unknown = selected - PIPELINES
    if unknown:
        raise ValueError(f"Pipeline no reconocido: {', '.join(sorted(unknown))}")

    started = time.time()
    manifest = {
        "status": "succeeded",
        "started_at": pd.Timestamp.now("UTC").isoformat(),
        "pipelines": {},
    }
    temporary_root = output_dir.parent / ".training-tmp"
    temporary_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="sport-center-ml-",
        dir=temporary_root,
    ) as temp:
        work = Path(temp)
        if "demand" in selected:
            manifest["pipelines"]["demand"] = train_demand(
                datasets_dir / "01_demanda_mensual_variantes.csv", work
            )
        if "recommendation" in selected:
            manifest["pipelines"]["recommendation"] = train_recommendations(
                datasets_dir / "02_recomendacion_productos_contenido.csv", work
            )
        if "clustering" in selected:
            manifest["pipelines"]["clustering"] = train_clustering(
                datasets_dir / "03_segmentacion_clientes_rfm.csv", work
            )

        for pipeline in manifest["pipelines"].values():
            for file_name in pipeline["files"]:
                source = work / file_name
                target_dir = models_dir if source.suffix == ".joblib" else output_dir
                atomic_copy(source, target_dir / file_name)

        source_files = {
            "demand": "01_demanda_mensual_variantes.csv",
            "recommendation": "02_recomendacion_productos_contenido.csv",
            "clustering": "03_segmentacion_clientes_rfm.csv",
        }
        for pipeline_name in selected:
            source_name = source_files[pipeline_name]
            atomic_copy(datasets_dir / source_name, output_dir / source_name)

    manifest["finished_at"] = pd.Timestamp.now("UTC").isoformat()
    manifest["duration_ms"] = int((time.time() - started) * 1000)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_file = output_dir / "training-manifest.json"
    temporary_manifest = manifest_file.with_suffix(".json.tmp")
    temporary_manifest.write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )
    os.replace(temporary_manifest, manifest_file)
    print(json.dumps(manifest, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
