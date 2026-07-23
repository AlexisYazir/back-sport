# Entrenamiento mensual

Sport Center entrena tres pipelines fuera del arranque de Nest:

- demanda mensual por variante;
- recomendaciones de productos por contenido;
- segmentacion RFM con K-Means.

La programacion y el historial se guardan en las tablas
`core.ml_training_schedules` y `core.ml_model_runs` de Neon. Estas tablas deben
crearse una sola vez antes de habilitar el proceso. La programacion inicial
ejecuta los tres pipelines el dia 1 de cada mes a las 03:00 en
`America/Mexico_City`.

## Modos de datos

`ML_DATASET_MODE=academic` usa exclusivamente el lote artificial de la materia
para demanda y clustering. Es el modo predeterminado mientras no exista
historial real suficiente.

`ML_DATASET_MODE=operational` reconstruye los datasets con pedidos reales cuyo
pago fue aprobado, excluye registros `ART_*` y deja fuera el mes en curso para
evitar entrenar con un periodo incompleto.

Para activar el modo operacional se recomienda contar, como minimo, con:

- siete meses cerrados de ventas;
- veinte clientes con compras pagadas en los ultimos doce meses;
- dos productos activos y con stock para recomendaciones.

## Dependencias

Instalar:

```text
python -m pip install -r ml/training/requirements.txt
```

El proceso de Nest tambien necesita `psql` disponible en `PATH`. Se pueden
ajustar los ejecutables con `ML_PYTHON_EXECUTABLE` y `PSQL_PATH`.

## Ejecucion manual

El administrador puede iniciar una corrida con:

```text
POST /reports/data-mining/training/run
```

El endpoint responde inmediatamente con el identificador de ejecucion. El
estado, las metricas y los artefactos se consultan en:

```text
GET /reports/data-mining/training/runs
```

Los resultados solo reemplazan a los anteriores cuando todos los pipelines
solicitados terminan correctamente.
