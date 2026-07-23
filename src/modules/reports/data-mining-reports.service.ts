import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { existsSync } from 'fs';
import { join } from 'path';
import { DataSource } from 'typeorm';
import * as XLSX from 'xlsx';

interface DemandSourceRow {
  id_producto: number;
  id_variante: number;
  nombre_producto: string;
  mes_objetivo: string;
  cantidad_mes_objetivo: number;
}

interface DemandResultRow extends DemandSourceRow {
  mes_proyectado: string;
  cantidad_hace_3_meses: number;
  cantidad_hace_2_meses: number;
  cantidad_mes_anterior: number;
  demanda_estimada: number;
  variacion_estimada: number;
  tendencia: 'creciente' | 'estable' | 'decreciente';
}

interface SegmentResultRow {
  id_usuario: number;
  fecha_corte: string;
  recencia_dias: number;
  frecuencia_12_meses: number;
  gasto_12_meses: number;
  cluster: number;
  segmento: string;
  accion_sugerida: string;
}

interface RecommendationSourceRow {
  id_producto: number;
  nombre_producto: string;
  descripcion: string;
  categoria: string;
  categoria_padre: string;
  marca: string;
  deportes: string;
  precio_promedio: number;
  stock_total: number;
  contenido_tfidf: string;
}

interface RecommendationResultRow {
  id_producto_origen: number;
  id_producto_recomendado: number;
  posicion: number;
  similitud: number;
}

@Injectable()
export class DataMiningReportsService {
  private readonly logger = new Logger(DataMiningReportsService.name);
  private readonly cache = new Map<string, Record<string, unknown>[]>();

  constructor(
    @InjectDataSource('readerConnection')
    private readonly readerDataSource: DataSource,
  ) {}

  clearCache(): void {
    this.cache.clear();
  }

  getDemandReport(): Record<string, unknown> {
    const history = this.readCsv<DemandSourceRow>(
      '01_demanda_mensual_variantes.csv',
    );
    const products = this.readCsv<DemandResultRow>(
      '01_resultados_prediccion_demanda.csv',
    ).sort((a, b) => b.demanda_estimada - a.demanda_estimada);

    const monthlyMap = new Map<string, { actual: number; records: number }>();
    for (const row of history) {
      const month = this.toMonthKey(row.mes_objetivo);
      const current = monthlyMap.get(month) ?? { actual: 0, records: 0 };
      current.actual += row.cantidad_mes_objetivo;
      current.records += 1;
      monthlyMap.set(month, current);
    }

    const trend = [...monthlyMap.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-12)
      .map(([month, values]) => ({ month, ...values }));

    const projectedDemand = products.reduce(
      (sum, row) => sum + row.demanda_estimada,
      0,
    );
    const lastDemand = products.reduce(
      (sum, row) => sum + row.cantidad_mes_objetivo,
      0,
    );
    const variation = projectedDemand - lastDemand;

    return {
      meta: {
        source: '01_demanda_mensual_variantes.csv',
        resultSource: '01_resultados_prediccion_demanda.csv',
        model: 'HistGradientBoostingRegressor',
        generatedAt: new Date().toISOString(),
        projectedMonth: products[0]?.mes_proyectado ?? null,
        historicalRecords: history.length,
      },
      summary: {
        variants: products.length,
        projectedDemand,
        lastDemand,
        variation,
        variationPercent:
          lastDemand > 0 ? this.round((variation / lastDemand) * 100) : 0,
        growing: products.filter((row) => row.tendencia === 'creciente').length,
        stable: products.filter((row) => row.tendencia === 'estable').length,
        declining: products.filter((row) => row.tendencia === 'decreciente')
          .length,
      },
      trend,
      products,
      methodology: {
        objective:
          'Estimar la demanda mensual por variante para apoyar compras e inventario.',
        features: [
          'Cantidad vendida hace tres meses',
          'Cantidad vendida hace dos meses',
          'Cantidad vendida el mes anterior',
        ],
        note: 'Las predicciones son apoyo para planeación y deben contrastarse con inventario y campañas vigentes.',
      },
    };
  }

  async getCustomerSegments(): Promise<Record<string, unknown>> {
    const rows = this.readCsv<SegmentResultRow>(
      '03_resultados_segmentacion_clientes.csv',
    );
    const userIds = rows.map((row) => row.id_usuario);
    const users = userIds.length
      ? await this.readerDataSource.query(
          `
          SELECT
            id_usuario,
            TRIM(CONCAT_WS(' ', nombre, "aPaterno")) AS nombre,
            email
          FROM core.users
          WHERE id_usuario = ANY($1::int[]);
          `,
          [userIds],
        )
      : [];

    const userMap = new Map<number, { nombre: string; email: string }>(
      users.map((user: any) => [
        Number(user.id_usuario),
        {
          nombre: user.nombre || `Cliente #${user.id_usuario}`,
          email: user.email || '',
        },
      ]),
    );

    const customers = rows.map((row) => ({
      ...row,
      name: userMap.get(row.id_usuario)?.nombre ?? `Cliente #${row.id_usuario}`,
      email: userMap.get(row.id_usuario)?.email ?? '',
    }));

    const groups = new Map<string, SegmentResultRow[]>();
    for (const row of rows) {
      const group = groups.get(row.segmento) ?? [];
      group.push(row);
      groups.set(row.segmento, group);
    }

    const segments = [...groups.entries()]
      .map(([name, segmentRows]) => ({
        name,
        cluster: segmentRows[0]?.cluster ?? 0,
        customers: segmentRows.length,
        percentage:
          rows.length > 0
            ? this.round((segmentRows.length / rows.length) * 100)
            : 0,
        averageRecency: this.average(
          segmentRows.map((row) => row.recencia_dias),
        ),
        averageFrequency: this.average(
          segmentRows.map((row) => row.frecuencia_12_meses),
        ),
        averageSpend: this.average(
          segmentRows.map((row) => row.gasto_12_meses),
        ),
        action: segmentRows[0]?.accion_sugerida ?? '',
      }))
      .sort((a, b) => b.averageSpend - a.averageSpend);

    return {
      meta: {
        source: '03_segmentacion_clientes_rfm.csv',
        resultSource: '03_resultados_segmentacion_clientes.csv',
        model: 'K-Means con análisis RFM',
        generatedAt: new Date().toISOString(),
        cutoffDate: rows[0]?.fecha_corte ?? null,
      },
      summary: {
        customers: rows.length,
        segments: segments.length,
        averageRecency: this.average(rows.map((row) => row.recencia_dias)),
        averageFrequency: this.average(
          rows.map((row) => row.frecuencia_12_meses),
        ),
        averageSpend: this.average(rows.map((row) => row.gasto_12_meses)),
        totalSpend: this.round(
          rows.reduce((sum, row) => sum + row.gasto_12_meses, 0),
        ),
      },
      segments,
      customers,
      methodology: {
        objective:
          'Agrupar clientes según recencia, frecuencia y gasto para orientar acciones comerciales.',
        variables: [
          'Recencia en días',
          'Frecuencia de compra en 12 meses',
          'Gasto en 12 meses',
        ],
      },
    };
  }

  async getProductRecommendations(
    productId: number,
    limit = 4,
  ): Promise<Record<string, unknown>> {
    const catalog = this.readCsv<RecommendationSourceRow>(
      '02_recomendacion_productos_contenido.csv',
    );
    const catalogMap = new Map(
      catalog.map((product) => [product.id_producto, product]),
    );
    if (!catalogMap.has(productId)) {
      return {
        productId,
        recommendations: [],
        model: 'TF-IDF y similitud de contenido entrenado',
      };
    }

    const precomputed = this.readCsv<RecommendationResultRow>(
      '02_resultados_recomendacion_productos.csv',
    )
      .filter((row) => row.id_producto_origen === productId)
      .sort((a, b) => a.posicion - b.posicion);
    const candidateIds = precomputed
      .slice(0, Math.max(limit * 3, 12))
      .map((row) => row.id_producto_recomendado);
    if (!candidateIds.length) {
      return {
        productId,
        recommendations: [],
        model: 'TF-IDF y similitud de contenido entrenado',
      };
    }

    const availableProducts = await this.readerDataSource.query(
      `
      SELECT
        p.id_producto,
        p.nombre,
        p.descripcion,
        m.nombre AS marca,
        c.nombre AS categoria,
        MIN(v.precio)::numeric AS precio,
        SUM(i.stock_actual)::int AS stock,
        (ARRAY_AGG(v.imagenes->>0 ORDER BY v.id_variante)
          FILTER (WHERE v.imagenes->>0 IS NOT NULL))[1] AS imagen
      FROM core.products p
      INNER JOIN core.product_variants v ON v.id_producto = p.id_producto
      INNER JOIN core.inventory i ON i.id_variante = v.id_variante AND i.stock_actual > 0
      LEFT JOIN core.marcas m ON m.id_marca = p.id_marca
      LEFT JOIN core.categories c ON c.id_categoria = p.id_categoria
      WHERE p.activo = TRUE
        AND p.id_producto = ANY($1::int[])
      GROUP BY p.id_producto, p.nombre, p.descripcion, m.nombre, c.nombre;
      `,
      [candidateIds],
    );

    const productMap = new Map<number, any>(
      availableProducts.map((product: any) => [
        Number(product.id_producto),
        product,
      ]),
    );
    const recommendations = precomputed
      .map((result) => {
        const candidate = catalogMap.get(result.id_producto_recomendado);
        const current = productMap.get(result.id_producto_recomendado);
        if (!candidate) return null;
        if (!current) return null;
        return {
          idProduct: result.id_producto_recomendado,
          name: current.nombre,
          description: current.descripcion,
          brand: current.marca || candidate.marca,
          category: current.categoria || candidate.categoria,
          sports: this.splitValues(candidate.deportes),
          price: Number(current.precio || candidate.precio_promedio),
          stock: Number(current.stock || 0),
          image: current.imagen || null,
          similarity: this.round(result.similitud * 100),
        };
      })
      .filter(Boolean)
      .slice(0, Math.min(Math.max(limit, 1), 10));

    return {
      productId,
      model: 'TF-IDF y similitud de contenido entrenado',
      recommendations,
    };
  }

  private readCsv<T>(fileName: string): T[] {
    const cached = this.cache.get(fileName);
    if (cached) return cached as T[];

    const filePath = this.resolveDataFile(fileName);
    const workbook = XLSX.readFile(filePath, { raw: false });
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const rawRows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, {
      defval: '',
    });
    const rows = rawRows.map((row) => this.normalizeRow(row));
    this.cache.set(fileName, rows);
    return rows as T[];
  }

  private resolveDataFile(fileName: string): string {
    const candidates = [
      join(process.cwd(), 'data', 'data-mining', fileName),
      join(process.cwd(), 'back-sport', 'data', 'data-mining', fileName),
      join(__dirname, '..', '..', '..', '..', 'data', 'data-mining', fileName),
    ];
    const filePath = candidates.find((candidate) => existsSync(candidate));
    if (!filePath) {
      this.logger.error(`No se encontró el dataset ${fileName}`);
      throw new NotFoundException('Dataset de análisis no disponible');
    }
    return filePath;
  }

  private normalizeRow(row: Record<string, unknown>): Record<string, unknown> {
    const numericColumns = new Set([
      'id_producto',
      'id_variante',
      'cantidad_hace_3_meses',
      'cantidad_hace_2_meses',
      'cantidad_mes_anterior',
      'cantidad_mes_objetivo',
      'demanda_estimada',
      'variacion_estimada',
      'id_usuario',
      'recencia_dias',
      'frecuencia_12_meses',
      'gasto_12_meses',
      'cluster',
      'precio_promedio',
      'stock_total',
      'id_producto_origen',
      'id_producto_recomendado',
      'posicion',
      'similitud',
    ]);
    return Object.fromEntries(
      Object.entries(row).map(([key, value]) => [
        key.replace(/^\uFEFF/, ''),
        numericColumns.has(key.replace(/^\uFEFF/, ''))
          ? Number(value || 0)
          : String(value ?? ''),
      ]),
    );
  }

  private buildTfidfVectors(documents: string[]): Map<string, number>[] {
    const tokens = documents.map((document) => this.tokenize(document));
    const documentFrequency = new Map<string, number>();
    for (const documentTokens of tokens) {
      for (const token of new Set(documentTokens)) {
        documentFrequency.set(token, (documentFrequency.get(token) ?? 0) + 1);
      }
    }

    return tokens.map((documentTokens) => {
      const vector = new Map<string, number>();
      const termFrequency = new Map<string, number>();
      for (const token of documentTokens) {
        termFrequency.set(token, (termFrequency.get(token) ?? 0) + 1);
      }
      for (const [token, count] of termFrequency) {
        const tf = count / Math.max(documentTokens.length, 1);
        const idf =
          Math.log(
            (1 + documents.length) / (1 + (documentFrequency.get(token) ?? 0)),
          ) + 1;
        vector.set(token, tf * idf);
      }
      return vector;
    });
  }

  private tokenize(value: string): string[] {
    const stopwords = new Set([
      'de',
      'la',
      'el',
      'en',
      'y',
      'para',
      'con',
      'un',
      'una',
      'los',
      'las',
      'del',
      'al',
      'por',
      'es',
      'color',
      'marca',
    ]);
    return this.normalizeText(value)
      .split(/\s+/)
      .filter((token) => token.length > 1 && !stopwords.has(token));
  }

  private normalizeText(value: string): string {
    return String(value || '')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  private cosineSimilarity(
    a: Map<string, number>,
    b: Map<string, number>,
  ): number {
    let dot = 0;
    let magnitudeA = 0;
    let magnitudeB = 0;
    for (const value of a.values()) magnitudeA += value * value;
    for (const value of b.values()) magnitudeB += value * value;
    for (const [token, value] of a) dot += value * (b.get(token) ?? 0);
    const denominator = Math.sqrt(magnitudeA) * Math.sqrt(magnitudeB);
    return denominator > 0 ? dot / denominator : 0;
  }

  private recommendationScore(
    source: RecommendationSourceRow,
    candidate: RecommendationSourceRow,
    textScore: number,
  ): number {
    const categoryScore = source.categoria === candidate.categoria ? 1 : 0;
    const brandScore = source.marca === candidate.marca ? 1 : 0;
    const sourceSports = new Set(
      this.splitValues(source.deportes).map((sport) => sport.toLowerCase()),
    );
    const candidateSports = new Set(
      this.splitValues(candidate.deportes).map((sport) => sport.toLowerCase()),
    );
    const union = new Set([...sourceSports, ...candidateSports]);
    const intersection = [...sourceSports].filter((sport) =>
      candidateSports.has(sport),
    );
    const sportsScore = union.size ? intersection.length / union.size : 0;
    const maxPrice = Math.max(
      source.precio_promedio,
      candidate.precio_promedio,
      1,
    );
    const priceScore = Math.max(
      0,
      1 -
        Math.abs(source.precio_promedio - candidate.precio_promedio) / maxPrice,
    );
    return (
      0.45 * textScore +
      0.2 * sportsScore +
      0.15 * categoryScore +
      0.1 * brandScore +
      0.1 * priceScore
    );
  }

  private splitValues(value: string): string[] {
    return String(value || '')
      .split('|')
      .map((item) => item.trim())
      .filter(Boolean);
  }

  private toMonthKey(value: string): string {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value.slice(0, 7);
    return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
  }

  private average(values: number[]): number {
    return values.length
      ? this.round(
          values.reduce((sum, value) => sum + value, 0) / values.length,
        )
      : 0;
  }

  private round(value: number): number {
    return Math.round((Number(value) + Number.EPSILON) * 100) / 100;
  }
}
