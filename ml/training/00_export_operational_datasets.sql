\set ON_ERROR_STOP on

\echo 'Exportando demanda operacional...'
\o 'data/data-mining/01_demanda_mensual_variantes.csv'
COPY (
  WITH paid_orders AS (
    SELECT o.id_orden, o.id_usuario, o.fecha_creacion
    FROM core.orders o
    INNER JOIN core.users u ON u.id_usuario = o.id_usuario
    WHERE o.fecha_creacion < date_trunc('month', CURRENT_DATE)
      AND COALESCE(u.email, '') NOT LIKE 'art.%@example.invalid'
      AND COALESCE(o.metodo_pago, '') NOT LIKE 'ART_%'
      AND EXISTS (
        SELECT 1
        FROM core.pagos pg
        WHERE pg.id_orden = o.id_orden
          AND pg.estado = 'aprobado'
      )
  ), bounds AS (
    SELECT
      GREATEST(
        date_trunc('month', min(fecha_creacion)),
        date_trunc('month', CURRENT_DATE) - INTERVAL '48 months'
      )::date AS first_month,
      (date_trunc('month', CURRENT_DATE) - INTERVAL '1 month')::date
        AS last_month
    FROM paid_orders
  ), months AS (
    SELECT generate_series(first_month, last_month, INTERVAL '1 month')::date
      AS month_start
    FROM bounds
    WHERE first_month IS NOT NULL
  ), variants AS (
    SELECT DISTINCT
      pv.id_producto,
      pv.id_variante,
      p.nombre AS nombre_producto
    FROM paid_orders po
    INNER JOIN core.order_items oi ON oi.id_orden = po.id_orden
    INNER JOIN core.product_variants pv ON pv.id_variante = oi.id_variante
    INNER JOIN core.products p ON p.id_producto = pv.id_producto
  ), operational_monthly AS (
    SELECT
      oi.id_variante,
      date_trunc('month', po.fecha_creacion)::date AS month_start,
      sum(oi.cantidad)::integer AS units
    FROM paid_orders po
    INNER JOIN core.order_items oi ON oi.id_orden = po.id_orden
    GROUP BY oi.id_variante, date_trunc('month', po.fecha_creacion)::date
  ), monthly_sales AS (
    SELECT
      v.id_producto,
      v.id_variante,
      v.nombre_producto,
      m.month_start,
      COALESCE(om.units, 0)::integer AS units
    FROM variants v
    CROSS JOIN months m
    LEFT JOIN operational_monthly om
      ON om.id_variante = v.id_variante
      AND om.month_start = m.month_start
  ), lagged AS (
    SELECT
      *,
      lag(units, 1) OVER w AS units_m1,
      lag(units, 2) OVER w AS units_m2,
      lag(units, 3) OVER w AS units_m3
    FROM monthly_sales
    WINDOW w AS (PARTITION BY id_variante ORDER BY month_start)
  )
  SELECT
    id_producto,
    id_variante,
    nombre_producto,
    month_start AS mes_objetivo,
    units_m3 AS cantidad_hace_3_meses,
    units_m2 AS cantidad_hace_2_meses,
    units_m1 AS cantidad_mes_anterior,
    units AS cantidad_mes_objetivo
  FROM lagged
  WHERE units_m3 IS NOT NULL
  ORDER BY month_start, id_variante
) TO STDOUT WITH (FORMAT CSV, HEADER true, ENCODING 'UTF8');
\o

\echo 'Exportando catalogo operacional para recomendaciones...'
\o 'data/data-mining/02_recomendacion_productos_contenido.csv'
COPY (
  WITH price_summary AS (
    SELECT
      pv.id_producto,
      count(*)::integer AS total_variantes,
      min(pv.precio)::numeric(12, 2) AS precio_min,
      max(pv.precio)::numeric(12, 2) AS precio_max,
      round(avg(pv.precio), 2)::numeric(12, 2) AS precio_promedio
    FROM core.product_variants pv
    GROUP BY pv.id_producto
  ), attribute_summary AS (
    SELECT
      pv.id_producto,
      COALESCE(
        string_agg(
          DISTINCT concat(attribute.key, ' ', attribute.value),
          ' ' ORDER BY concat(attribute.key, ' ', attribute.value)
        ),
        ''
      ) AS atributos
    FROM core.product_variants pv
    LEFT JOIN LATERAL jsonb_each_text(
      COALESCE(pv.atributos, '{}'::jsonb)
    ) attribute ON true
    GROUP BY pv.id_producto
  ), stock_summary AS (
    SELECT
      pv.id_producto,
      COALESCE(sum(GREATEST(i.stock_actual, 0)), 0)::integer AS stock_total
    FROM core.product_variants pv
    LEFT JOIN core.inventory i ON i.id_variante = pv.id_variante
    GROUP BY pv.id_producto
  ), sport_summary AS (
    SELECT
      pd.id_producto,
      string_agg(DISTINCT d.nombre, '|' ORDER BY d.nombre) AS deportes
    FROM core.product_deportes pd
    INNER JOIN core.deportes d ON d.id_deporte = pd.id_deporte
    GROUP BY pd.id_producto
  )
  SELECT
    p.id_producto,
    p.nombre AS nombre_producto,
    p.descripcion,
    c.id_categoria,
    c.nombre AS categoria,
    COALESCE(parent_category.nombre, '') AS categoria_padre,
    m.id_marca,
    m.nombre AS marca,
    COALESCE(ss.deportes, 'Sin deporte') AS deportes,
    attributes.atributos,
    prices.total_variantes,
    prices.precio_min,
    prices.precio_max,
    prices.precio_promedio,
    stocks.stock_total,
    p.activo,
    (p.activo AND stocks.stock_total > 0) AS disponible,
    lower(trim(concat_ws(
      ' ',
      p.nombre,
      p.descripcion,
      attributes.atributos
    ))) AS contenido_tfidf
  FROM core.products p
  INNER JOIN core.categories c ON c.id_categoria = p.id_categoria
  LEFT JOIN core.categories parent_category
    ON parent_category.id_categoria = c.id_padre
  INNER JOIN core.marcas m ON m.id_marca = p.id_marca
  INNER JOIN price_summary prices ON prices.id_producto = p.id_producto
  INNER JOIN attribute_summary attributes
    ON attributes.id_producto = p.id_producto
  INNER JOIN stock_summary stocks ON stocks.id_producto = p.id_producto
  LEFT JOIN sport_summary ss ON ss.id_producto = p.id_producto
  WHERE p.activo = true
    AND stocks.stock_total > 0
  ORDER BY p.id_producto
) TO STDOUT WITH (FORMAT CSV, HEADER true, ENCODING 'UTF8');
\o

\echo 'Exportando segmentacion RFM operacional...'
\o 'data/data-mining/03_segmentacion_clientes_rfm.csv'
COPY (
  WITH params AS (
    SELECT date_trunc('month', CURRENT_DATE)::date AS cutoff_date
  ), paid_orders AS (
    SELECT o.id_orden, o.id_usuario, o.fecha_creacion, o.total
    FROM core.orders o
    INNER JOIN core.users u ON u.id_usuario = o.id_usuario
    CROSS JOIN params p
    WHERE o.fecha_creacion < p.cutoff_date
      AND COALESCE(u.email, '') NOT LIKE 'art.%@example.invalid'
      AND COALESCE(o.metodo_pago, '') NOT LIKE 'ART_%'
      AND EXISTS (
        SELECT 1
        FROM core.pagos pg
        WHERE pg.id_orden = o.id_orden
          AND pg.estado = 'aprobado'
      )
  )
  SELECT
    po.id_usuario,
    p.cutoff_date AS fecha_corte,
    (p.cutoff_date - max(po.fecha_creacion)::date)::integer AS recencia_dias,
    count(DISTINCT po.id_orden) FILTER (
      WHERE po.fecha_creacion >= p.cutoff_date - INTERVAL '12 months'
    )::integer AS frecuencia_12_meses,
    COALESCE(sum(po.total) FILTER (
      WHERE po.fecha_creacion >= p.cutoff_date - INTERVAL '12 months'
    ), 0)::numeric(14, 2) AS gasto_12_meses
  FROM paid_orders po
  CROSS JOIN params p
  GROUP BY po.id_usuario, p.cutoff_date
  HAVING count(DISTINCT po.id_orden) FILTER (
    WHERE po.fecha_creacion >= p.cutoff_date - INTERVAL '12 months'
  ) > 0
  ORDER BY po.id_usuario
) TO STDOUT WITH (FORMAT CSV, HEADER true, ENCODING 'UTF8');
\o

\echo 'Exportacion operacional terminada.'
