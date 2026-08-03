import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import {
  MlInferenceService,
  ProductRecommendationFeatures,
} from '../ml-inference/ml-inference.service';

@Injectable()
export class ProductRecommendationsService {
  constructor(
    @InjectDataSource('readerConnection')
    private readonly readerDataSource: DataSource,
    private readonly mlInferenceService: MlInferenceService,
  ) {}

  async getRecommendations(productId: number, limit = 10): Promise<any> {
    // 1. Verificar que el producto existe
    const product = await this.getProductFeatures(productId);
    if (!product) {
      throw new NotFoundException('Producto no encontrado');
    }

    // 2. OPTIMIZACIÓN: Enviar solo el ID a FastAPI
    // Ya no enviamos todo el producto, solo el ID
    const mlResponse = await this.mlInferenceService.recommendById(
      productId,
      Math.min(limit + 8, 20), // Pedir más para compensar filtros
    );

    // 3. Obtener IDs de los productos recomendados
    const ids = mlResponse.recommendations
      .map((item) => Number(item.id_producto))
      .filter((id) => Number.isFinite(id) && id !== productId);

    // 4. Enriquecer con datos actuales de la base de datos
    const currentProducts = await this.getCurrentProducts(ids);
    const productMap = new Map(currentProducts.map((item) => [item.idProduct, item]));
    const used = new Set<number>();
    const recommendations: any[] = [];

    for (const item of mlResponse.recommendations) {
      const id = Number(item.id_producto);
      const current = productMap.get(id);
      if (!current || used.has(id) || id === productId) continue;
      used.add(id);
      recommendations.push({
        ...current,
        similarity: Number(Number(item.score || 0).toFixed(4)),
      });
      if (recommendations.length >= limit) break;
    }

    return {
      productId,
      model: mlResponse.algorithm || 'Filtrado basado en contenido',
      modelVersion: mlResponse.model_version,
      totalRecommended: mlResponse.recommendations.length,
      recommendations,
    };
  }

  private async getProductFeatures(
    productId: number,
  ): Promise<ProductRecommendationFeatures | null> {
    const rows = await this.readerDataSource.query(
      `
      WITH price_summary AS (
        SELECT
          id_producto,
          AVG(precio)::numeric(12,2) AS precio_promedio
        FROM core.product_variants
        GROUP BY id_producto
      ),
      attr AS (
        SELECT
          pv.id_producto,
          string_agg(DISTINCT av.key || ': ' || av.value, ' | ' ORDER BY av.key || ': ' || av.value) AS atributos
        FROM core.product_variants pv
        LEFT JOIN LATERAL jsonb_each_text(COALESCE(pv.atributos, '{}'::jsonb)) av ON true
        GROUP BY pv.id_producto
      ),
      sports AS (
        SELECT
          pd.id_producto,
          array_agg(DISTINCT d.nombre ORDER BY d.nombre) AS deportes
        FROM core.product_deportes pd
        INNER JOIN core.deportes d ON d.id_deporte = pd.id_deporte
        GROUP BY pd.id_producto
      )
      SELECT
        p.id_producto,
        p.nombre AS nombre_producto,
        COALESCE(p.descripcion, '') AS descripcion,
        COALESCE(c.nombre, '') AS categoria,
        COALESCE(cp.nombre, '') AS categoria_padre,
        COALESCE(m.nombre, '') AS marca,
        COALESCE(sports.deportes, ARRAY[]::varchar[]) AS deportes,
        COALESCE(attr.atributos, '') AS atributos,
        COALESCE(price_summary.precio_promedio, 0)::float AS precio_promedio
      FROM core.products p
      LEFT JOIN core.categories c ON c.id_categoria = p.id_categoria
      LEFT JOIN core.categories cp ON cp.id_categoria = c.id_padre
      LEFT JOIN core.marcas m ON m.id_marca = p.id_marca
      LEFT JOIN price_summary ON price_summary.id_producto = p.id_producto
      LEFT JOIN attr ON attr.id_producto = p.id_producto
      LEFT JOIN sports ON sports.id_producto = p.id_producto
      WHERE p.id_producto = $1
        AND p.activo = true;
      `,
      [productId],
    );

    if (!rows[0]) return null;
    const row = rows[0];
    return {
      id_producto: Number(row.id_producto),
      nombre_producto: row.nombre_producto,
      descripcion: row.descripcion || '',
      categoria: row.categoria || '',
      categoria_padre: row.categoria_padre || '',
      marca: row.marca || '',
      deportes: Array.isArray(row.deportes) ? row.deportes : [],
      atributos: row.atributos || '',
      precio_promedio: Number(row.precio_promedio || 0),
    };
  }

  private async getCurrentProducts(productIds: number[]): Promise<any[]> {
    if (!productIds.length) return [];

    const rows = await this.readerDataSource.query(
      `
      WITH variant_summary AS (
        SELECT
          pv.id_producto,
          MIN(pv.precio)::float AS precio,
          COALESCE((array_agg(pv.imagenes->>0 ORDER BY pv.id_variante)
            FILTER (WHERE pv.imagenes IS NOT NULL AND jsonb_array_length(pv.imagenes) > 0))[1], '') AS imagen,
          SUM(COALESCE(i.stock_actual, 0))::int AS stock
        FROM core.product_variants pv
        LEFT JOIN core.inventory i ON i.id_variante = pv.id_variante
        GROUP BY pv.id_producto
      ),
      sports AS (
        SELECT
          pd.id_producto,
          array_agg(DISTINCT d.nombre ORDER BY d.nombre) AS deportes
        FROM core.product_deportes pd
        INNER JOIN core.deportes d ON d.id_deporte = pd.id_deporte
        GROUP BY pd.id_producto
      )
      SELECT
        p.id_producto AS "idProduct",
        p.nombre AS "name",
        COALESCE(p.descripcion, '') AS "description",
        COALESCE(m.nombre, '') AS "brand",
        COALESCE(c.nombre, '') AS "category",
        COALESCE(sports.deportes, ARRAY[]::varchar[]) AS "sports",
        COALESCE(variant_summary.precio, 0)::float AS "price",
        COALESCE(variant_summary.stock, 0)::int AS "stock",
        NULLIF(variant_summary.imagen, '') AS "image"
      FROM core.products p
      INNER JOIN variant_summary ON variant_summary.id_producto = p.id_producto
      LEFT JOIN core.categories c ON c.id_categoria = p.id_categoria
      LEFT JOIN core.marcas m ON m.id_marca = p.id_marca
      LEFT JOIN sports ON sports.id_producto = p.id_producto
      WHERE p.id_producto = ANY($1::int[])
        AND p.activo = true
        AND COALESCE(variant_summary.stock, 0) > 0;
      `,
      [productIds],
    );

    return rows.map((row) => ({
      idProduct: Number(row.idProduct),
      name: row.name,
      description: row.description || '',
      brand: row.brand || '',
      category: row.category || '',
      sports: Array.isArray(row.sports) ? row.sports : [],
      price: Number(row.price || 0),
      stock: Number(row.stock || 0),
      image: row.image || null,
    }));
  }
}