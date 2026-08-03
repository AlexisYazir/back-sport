import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import {
  DemandPredictionRequest,
  MlInferenceService,
} from '../ml-inference/ml-inference.service';

interface VariantDemandFeatures {
  id_producto: number;
  id_variante: number;
  sku: string;
  nombre_producto: string;
  imagen: string | null;
  mes_proyectado: string;
  cantidad_hace_3_meses: number;
  cantidad_hace_2_meses: number;
  cantidad_mes_anterior: number;
}

@Injectable()
export class DemandForecastService {
  constructor(
    @InjectDataSource('adminConnection')
    private readonly adminDataSource: DataSource,
    private readonly mlInferenceService: MlInferenceService,
  ) {}

  async getDemandReport(): Promise<any> {
    const [features, trend] = await Promise.all([
      this.getAllVariantFeatures(),
      this.getHistoricalTrend(),
    ]);

    const predictions = await Promise.all(
      features.map(async (row) => {
        // Calcular todas las features antes de enviar
        const enrichedPayload = this.enrichDemandFeatures(row);
        const prediction = await this.mlInferenceService.predictDemand(
          enrichedPayload,
        );
        return this.toDemandProduct(row, prediction.predicted_units);
      }),
    );

    const projectedDemand = predictions.reduce(
      (sum, row) => sum + row.demanda_estimada,
      0,
    );
    const lastDemand = predictions.reduce(
      (sum, row) => sum + row.cantidad_mes_anterior,
      0,
    );
    const variation = projectedDemand - lastDemand;

    return {
      meta: {
        source: 'PostgreSQL + FastAPI',
        resultSource: 'Modelo .joblib en memoria',
        model: 'Regresión mensual por variante',
        generatedAt: new Date().toISOString(),
        projectedMonth: features[0]?.mes_proyectado || null,
        historicalRecords: trend.reduce((sum, row) => sum + Number(row.records || 0), 0),
      },
      summary: {
        variants: predictions.length,
        projectedDemand,
        lastDemand,
        variation,
        variationPercent: lastDemand > 0 ? Number(((variation / lastDemand) * 100).toFixed(1)) : 0,
        growing: predictions.filter((row) => row.tendencia === 'creciente').length,
        stable: predictions.filter((row) => row.tendencia === 'estable').length,
        declining: predictions.filter((row) => row.tendencia === 'decreciente').length,
      },
      trend,
      products: predictions,
      methodology: {
        objective: 'Estimar la demanda del siguiente mes por variante para apoyar compras e inventario.',
        features: [
          'Ventas de hace 3 meses',
          'Ventas de hace 2 meses',
          'Ventas del mes anterior',
          'Features cíclicas (mes_num, mes_sin, mes_cos)',
          'Features de tendencia (lag_mean, lag_weighted, lag_trend)',
          'Features de volatilidad (lag_volatility, lag_min, lag_max)',
        ],
        note: 'La predicción se calcula con los tres meses completos anteriores; los meses sin ventas se completan con cero.',
      },
    };
  }

  async predictVariant(idVariante: number): Promise<any> {
    const row = await this.getVariantFeatures(idVariante);
    if (!row) {
      throw new NotFoundException('Variante no encontrada o inactiva');
    }

    // Calcular todas las features antes de enviar
    const enrichedPayload = this.enrichDemandFeatures(row);
    const prediction = await this.mlInferenceService.predictDemand(
      enrichedPayload,
    );

    return {
      id_variante: row.id_variante,
      sku: row.sku,
      id_producto: row.id_producto,
      nombre_producto: row.nombre_producto,
      imagen: row.imagen,
      mes_objetivo: row.mes_proyectado,
      historial: {
        cantidad_hace_3_meses: row.cantidad_hace_3_meses,
        cantidad_hace_2_meses: row.cantidad_hace_2_meses,
        cantidad_mes_anterior: row.cantidad_mes_anterior,
      },
      features_adicionales: {
        mes_num: enrichedPayload.mes_num,
        lag_mean: enrichedPayload.lag_mean,
        lag_weighted: enrichedPayload.lag_weighted,
        lag_trend: enrichedPayload.lag_trend,
        lag_volatility: enrichedPayload.lag_volatility,
        zero_lags: enrichedPayload.zero_lags,
      },
      unidades_predichas: Math.max(0, Math.round(prediction.predicted_units)),
      modelVersion: prediction.model_version,
      algorithm: prediction.algorithm,
    };
  }

  /**
   * Enriquecer las features de demanda con todas las variables que el modelo espera
   * Esto es CRÍTICO para que el modelo funcione correctamente
   */
  private enrichDemandFeatures(row: VariantDemandFeatures): DemandPredictionRequest {
    const lags = [
      row.cantidad_hace_3_meses,
      row.cantidad_hace_2_meses,
      row.cantidad_mes_anterior,
    ];

    // Calcular mes objetivo
    let targetDate: Date;
    if (row.mes_proyectado) {
      targetDate = new Date(row.mes_proyectado + '-01');
    } else {
      targetDate = new Date();
      targetDate.setDate(1);
    }
    const month = targetDate.getMonth() + 1; // 1-12

    // Calcular todas las features derivadas
    const lagMean = lags.reduce((a, b) => a + b, 0) / lags.length;
    const lagWeighted = lags[0] * 0.2 + lags[1] * 0.3 + lags[2] * 0.5;
    const lagTrend = lags[2] - lags[0];
    const lagLastDelta = lags[2] - lags[1];
    const lagVolatility = this.calculateStdDev(lags);
    const lagMin = Math.min(...lags);
    const lagMax = Math.max(...lags);
    const zeroLags = lags.filter((v) => v === 0).length;

    return {
      id_variante: row.id_variante,
      cantidad_hace_3_meses: row.cantidad_hace_3_meses,
      cantidad_hace_2_meses: row.cantidad_hace_2_meses,
      cantidad_mes_anterior: row.cantidad_mes_anterior,
      mes_objetivo: row.mes_proyectado,
      // Features cíclicas para capturar estacionalidad
      mes_num: month,
      mes_sin: Math.sin((2 * Math.PI * month) / 12),
      mes_cos: Math.cos((2 * Math.PI * month) / 12),
      // One-hot encoding de trimestres
      q1: month >= 1 && month <= 3 ? 1 : 0,
      q2: month >= 4 && month <= 6 ? 1 : 0,
      q3: month >= 7 && month <= 9 ? 1 : 0,
      q4: month >= 10 && month <= 12 ? 1 : 0,
      // Features de tendencia
      lag_mean: Math.round(lagMean * 100) / 100,
      lag_weighted: Math.round(lagWeighted * 100) / 100,
      lag_trend: lagTrend,
      lag_last_delta: lagLastDelta,
      // Features de volatilidad
      lag_volatility: Math.round(lagVolatility * 100) / 100,
      lag_min: lagMin,
      lag_max: lagMax,
      // Contador de meses sin ventas
      zero_lags: zeroLags,
    };
  }

  private calculateStdDev(values: number[]): number {
    if (values.length === 0) return 0;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const squaredDiffs = values.map((v) => Math.pow(v - mean, 2));
    const variance = squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
    return Math.sqrt(variance);
  }

  private toDemandProduct(row: VariantDemandFeatures, predictedUnits: number) {
    const demandaEstimada = Math.max(0, Math.round(Number(predictedUnits) || 0));
    const variacion = demandaEstimada - row.cantidad_mes_anterior;
    const tendencia =
      Math.abs(variacion) <= 2
        ? 'estable'
        : variacion > 0
          ? 'creciente'
          : 'decreciente';

    return {
      id_producto: row.id_producto,
      id_variante: row.id_variante,
      sku: row.sku,
      nombre_producto: row.nombre_producto,
      imagen: row.imagen,
      mes_objetivo: row.mes_proyectado,
      mes_proyectado: row.mes_proyectado,
      cantidad_hace_3_meses: row.cantidad_hace_3_meses,
      cantidad_hace_2_meses: row.cantidad_hace_2_meses,
      cantidad_mes_anterior: row.cantidad_mes_anterior,
      cantidad_mes_objetivo: 0,
      demanda_estimada: demandaEstimada,
      variacion_estimada: variacion,
      tendencia,
    };
  }

  private async getVariantFeatures(
    idVariante: number,
  ): Promise<VariantDemandFeatures | null> {
    const rows = await this.adminDataSource.query(
      this.featuresSql('WHERE pv.id_variante = $1'),
      [idVariante],
    );
    return rows[0] ? this.normalizeFeatureRow(rows[0]) : null;
  }

  private async getAllVariantFeatures(): Promise<VariantDemandFeatures[]> {
    const rows = await this.adminDataSource.query(this.featuresSql(''));
    return rows.map((row) => this.normalizeFeatureRow(row));
  }

  private normalizeFeatureRow(row: any): VariantDemandFeatures {
    return {
      id_producto: Number(row.id_producto),
      id_variante: Number(row.id_variante),
      sku: String(row.sku ?? '').trim(),
      nombre_producto: String(row.nombre_producto ?? '').trim(),
      imagen: row.imagen ? String(row.imagen).trim() : null,
      mes_proyectado: row.mes_proyectado,
      cantidad_hace_3_meses: Number(row.cantidad_hace_3_meses || 0),
      cantidad_hace_2_meses: Number(row.cantidad_hace_2_meses || 0),
      cantidad_mes_anterior: Number(row.cantidad_mes_anterior || 0),
    };
  }

  private featuresSql(extraWhere: string): string {
    return `
      WITH params AS (
        SELECT date_trunc('month', CURRENT_DATE)::date AS mes_objetivo
      ),
      variantes AS (
        SELECT
          p.id_producto,
          pv.id_variante,
          COALESCE(NULLIF(pv.sku, ''), CONCAT('Variante #', pv.id_variante)) AS sku,
          NULLIF(pv.imagenes->>0, '') AS imagen,
          p.nombre AS nombre_producto
        FROM core.product_variants pv
        INNER JOIN core.products p ON p.id_producto = pv.id_producto
        ${extraWhere}
          ${extraWhere ? 'AND' : 'WHERE'} p.activo = true
      ),
      ventas AS (
        SELECT
          oi.id_variante,
          date_trunc('month', o.fecha_creacion)::date AS mes,
          SUM(oi.cantidad)::int AS cantidad
        FROM core.orders o
        INNER JOIN core.order_items oi ON oi.id_orden = o.id_orden
        LEFT JOIN core.pagos pg ON pg.id_orden = o.id_orden
        CROSS JOIN params
        WHERE o.fecha_creacion >= params.mes_objetivo - INTERVAL '3 months'
          AND o.fecha_creacion < params.mes_objetivo
          AND (
            LOWER(COALESCE(o.estado, '')) IN ('pagado', 'preparando', 'enviado', 'en_transito', 'entregado')
            OR LOWER(COALESCE(pg.estado, '')) IN ('aprobado', 'approved', 'pagado')
          )
        GROUP BY oi.id_variante, date_trunc('month', o.fecha_creacion)::date
      )
      SELECT
        v.id_producto,
        v.id_variante,
        v.sku,
        v.imagen,
        v.nombre_producto,
        to_char(params.mes_objetivo, 'YYYY-MM-01') AS mes_proyectado,
        COALESCE(SUM(ventas.cantidad) FILTER (WHERE ventas.mes = params.mes_objetivo - INTERVAL '3 months'), 0)::int AS cantidad_hace_3_meses,
        COALESCE(SUM(ventas.cantidad) FILTER (WHERE ventas.mes = params.mes_objetivo - INTERVAL '2 months'), 0)::int AS cantidad_hace_2_meses,
        COALESCE(SUM(ventas.cantidad) FILTER (WHERE ventas.mes = params.mes_objetivo - INTERVAL '1 month'), 0)::int AS cantidad_mes_anterior
      FROM variantes v
      CROSS JOIN params
      LEFT JOIN ventas ON ventas.id_variante = v.id_variante
      GROUP BY v.id_producto, v.id_variante, v.sku, v.imagen, v.nombre_producto, params.mes_objetivo
      ORDER BY v.id_variante ASC;
    `;
  }

  private async getHistoricalTrend(): Promise<any[]> {
    const rows = await this.adminDataSource.query(`
      WITH meses AS (
        SELECT generate_series(
          date_trunc('month', CURRENT_DATE)::date - INTERVAL '12 months',
          date_trunc('month', CURRENT_DATE)::date - INTERVAL '1 month',
          INTERVAL '1 month'
        )::date AS mes
      ),
      ventas AS (
        SELECT
          date_trunc('month', o.fecha_creacion)::date AS mes,
          SUM(oi.cantidad)::int AS actual,
          COUNT(*)::int AS records
        FROM core.orders o
        INNER JOIN core.order_items oi ON oi.id_orden = o.id_orden
        LEFT JOIN core.pagos pg ON pg.id_orden = o.id_orden
        WHERE o.fecha_creacion >= date_trunc('month', CURRENT_DATE)::date - INTERVAL '12 months'
          AND o.fecha_creacion < date_trunc('month', CURRENT_DATE)::date
          AND (
            LOWER(COALESCE(o.estado, '')) IN ('pagado', 'preparando', 'enviado', 'en_transito', 'entregado')
            OR LOWER(COALESCE(pg.estado, '')) IN ('aprobado', 'approved', 'pagado')
          )
        GROUP BY date_trunc('month', o.fecha_creacion)::date
      )
      SELECT
        to_char(meses.mes, 'YYYY-MM-01') AS month,
        COALESCE(ventas.actual, 0)::int AS actual,
        COALESCE(ventas.records, 0)::int AS records
      FROM meses
      LEFT JOIN ventas ON ventas.mes = meses.mes
      ORDER BY meses.mes ASC;
    `);

    return rows.map((row) => ({
      month: row.month,
      actual: Number(row.actual || 0),
      records: Number(row.records || 0),
    }));
  }
}