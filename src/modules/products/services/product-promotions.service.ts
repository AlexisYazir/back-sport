/* eslint-disable */
import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

import {
  CreatePromotionDto,
  UpdatePromotionDto,
  UpdateShippingMethodDto,
} from '../dto/promotions/promotion.dto';

@Injectable()
export class ProductPromotionsService {
  private readonly logger = new Logger(ProductPromotionsService.name);

  constructor(
    @InjectDataSource('readerConnection')
    private readonly readerDataSource: DataSource,
    @InjectDataSource('editorConnection')
    private readonly editorDataSource: DataSource,
  ) {}

  async getPromotions(admin = false): Promise<any[]> {
    const where = admin
      ? ''
      : `WHERE p.activo = true AND CURRENT_TIMESTAMP BETWEEN p.inicia_en AND p.termina_en`;

    const rows = await this.readerDataSource.query(`
      SELECT
        p.*,
        COALESCE(redemptions.usos, 0)::int AS usos,
        COALESCE(targets.targets, '[]'::jsonb) AS targets
      FROM core.promotions p
      LEFT JOIN (
        SELECT id_promocion, COUNT(*)::int AS usos
        FROM core.promotion_redemptions
        GROUP BY id_promocion
      ) redemptions ON redemptions.id_promocion = p.id_promocion
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(
          jsonb_build_object(
            'id_target', pt.id_promotion_target,
            'tipo_objetivo', pt.tipo_objetivo,
            'id_objetivo', pt.id_objetivo
          )
        ) AS targets
        FROM core.promotion_targets pt
        WHERE pt.id_promocion = p.id_promocion
      ) targets ON true
      ${where}
      ORDER BY p.activo DESC, p.inicia_en DESC, p.id_promocion DESC;
    `);

    return rows.map((promotion) => this.normalizePromotion(promotion));
  }

  async getOfferProducts(): Promise<any[]> {
    const rows = await this.readerDataSource.query(`
      WITH active_promotions AS (
        SELECT *
        FROM core.promotions
        WHERE activo = true
          AND tipo IN ('porcentaje', 'monto_fijo')
          AND CURRENT_TIMESTAMP BETWEEN inicia_en AND termina_en
      ),
      promo_targets AS (
        SELECT
          ap.*,
          pt.tipo_objetivo,
          pt.id_objetivo
        FROM active_promotions ap
        LEFT JOIN core.promotion_targets pt
          ON pt.id_promocion = ap.id_promocion
      )
      SELECT DISTINCT ON (p.id_producto)
        p.id_producto,
        p.nombre,
        p.descripcion,
        p.activo,
        m.nombre AS marca,
        c.nombre AS categoria,
        COALESCE(v.precio, 0) AS precio,
        COALESCE(
          CASE
            WHEN pt.tipo = 'porcentaje' THEN pt.valor
            WHEN pt.tipo = 'monto_fijo' AND COALESCE(v.precio, 0) > 0
              THEN LEAST(90, ROUND((pt.valor / COALESCE(v.precio, 1)) * 100, 0))
            ELSE 0
          END,
          0
        ) AS descuento,
        pt.id_promocion,
        pt.nombre AS promocion,
        pt.codigo,
        COALESCE(v.imagenes, '[]'::jsonb) AS imagenes,
        v.id_variante,
        v.sku
      FROM core.products p
      INNER JOIN core.product_variants v
        ON v.id_producto = p.id_producto
      LEFT JOIN core.marcas m
        ON m.id_marca = p.id_marca
      LEFT JOIN core.categories c
        ON c.id_categoria = p.id_categoria
      INNER JOIN promo_targets pt
        ON pt.tipo_objetivo IS NULL
        OR (pt.tipo_objetivo = 'producto' AND pt.id_objetivo = p.id_producto)
        OR (pt.tipo_objetivo = 'variante' AND pt.id_objetivo = v.id_variante)
        OR (pt.tipo_objetivo = 'marca' AND pt.id_objetivo = p.id_marca)
        OR (pt.tipo_objetivo = 'categoria' AND pt.id_objetivo = p.id_categoria)
      WHERE p.activo = true
      ORDER BY p.id_producto, descuento DESC, pt.inicia_en DESC;
    `);

    return rows.map((row) => ({
      ...row,
      id_producto: Number(row.id_producto),
      id_variante: Number(row.id_variante),
      precio: Number(row.precio || 0),
      descuento: Number(row.descuento || 0),
      id_promocion: Number(row.id_promocion),
      imagen: Array.isArray(row.imagenes) ? row.imagenes[0] : null,
    }));
  }

  async createPromotion(
    dto: CreatePromotionDto,
    userId: number,
  ): Promise<any> {
    this.validatePromotionDates(dto.inicia_en, dto.termina_en);

    const rows = await this.editorDataSource.query(
      `
      INSERT INTO core.promotions (
        nombre,
        descripcion,
        codigo,
        tipo,
        valor,
        descuento_maximo,
        compra_minima,
        uso_maximo,
        uso_por_usuario,
        inicia_en,
        termina_en,
        activo,
        creado_por,
        fecha_creacion,
        fecha_actualizacion
      )
      VALUES ($1, $2, NULLIF(UPPER(TRIM($3)), ''), $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      RETURNING *;
      `,
      [
        this.cleanText(dto.nombre, 120),
        this.cleanOptionalText(dto.descripcion, 500),
        dto.codigo || null,
        dto.tipo,
        Number(dto.valor || 0),
        dto.descuento_maximo ?? null,
        dto.compra_minima ?? 0,
        dto.uso_maximo ?? null,
        dto.uso_por_usuario ?? null,
        dto.inicia_en,
        dto.termina_en,
        dto.activo !== false,
        userId,
      ],
    );

    return this.normalizePromotion(rows[0]);
  }

  async updatePromotion(
    id: number,
    dto: UpdatePromotionDto,
    userId: number,
  ): Promise<any> {
    this.validatePositiveInteger(id, 'La promoción debe ser válida');

    if (dto.inicia_en && dto.termina_en) {
      this.validatePromotionDates(dto.inicia_en, dto.termina_en);
    }

    const rows = await this.editorDataSource.query(
      `
      UPDATE core.promotions
      SET nombre = COALESCE($2, nombre),
          descripcion = COALESCE($3, descripcion),
          codigo = COALESCE(NULLIF(UPPER(TRIM($4)), ''), codigo),
          tipo = COALESCE($5, tipo),
          valor = COALESCE($6, valor),
          descuento_maximo = COALESCE($7, descuento_maximo),
          compra_minima = COALESCE($8, compra_minima),
          uso_maximo = COALESCE($9, uso_maximo),
          uso_por_usuario = COALESCE($10, uso_por_usuario),
          inicia_en = COALESCE($11::timestamp, inicia_en),
          termina_en = COALESCE($12::timestamp, termina_en),
          activo = COALESCE($13, activo),
          fecha_actualizacion = CURRENT_TIMESTAMP
      WHERE id_promocion = $1
      RETURNING *;
      `,
      [
        id,
        dto.nombre ? this.cleanText(dto.nombre, 120) : null,
        dto.descripcion ? this.cleanOptionalText(dto.descripcion, 500) : null,
        dto.codigo || null,
        dto.tipo || null,
        dto.valor ?? null,
        dto.descuento_maximo ?? null,
        dto.compra_minima ?? null,
        dto.uso_maximo ?? null,
        dto.uso_por_usuario ?? null,
        dto.inicia_en || null,
        dto.termina_en || null,
        dto.activo ?? null,
      ],
    );

    if (!rows[0]) {
      throw new BadRequestException('La promoción no existe');
    }

    return this.normalizePromotion(rows[0]);
  }

  async getShippingMethods(admin = false): Promise<any[]> {
    const rows = await this.readerDataSource.query(`
      SELECT *
      FROM core.shipping_methods
      ${admin ? '' : 'WHERE activo = true'}
      ORDER BY activo DESC, costo_base ASC, id_metodo_envio ASC;
    `);

    return rows.map((row) => this.normalizeShippingMethod(row));
  }

  async updateShippingMethod(
    id: number,
    dto: UpdateShippingMethodDto,
  ): Promise<any> {
    this.validatePositiveInteger(id, 'El método de envío debe ser válido');

    const rows = await this.editorDataSource.query(
      `
      UPDATE core.shipping_methods
      SET nombre = COALESCE($2, nombre),
          descripcion = COALESCE($3, descripcion),
          costo_base = COALESCE($4, costo_base),
          envio_gratis_desde = COALESCE($5, envio_gratis_desde),
          dias_min = COALESCE($6, dias_min),
          dias_max = COALESCE($7, dias_max),
          activo = COALESCE($8, activo),
          fecha_actualizacion = CURRENT_TIMESTAMP
      WHERE id_metodo_envio = $1
      RETURNING *;
      `,
      [
        id,
        dto.nombre ? this.cleanText(dto.nombre, 100) : null,
        dto.descripcion ? this.cleanOptionalText(dto.descripcion, 255) : null,
        dto.costo_base ?? null,
        dto.envio_gratis_desde ?? null,
        dto.dias_min ?? null,
        dto.dias_max ?? null,
        dto.activo ?? null,
      ],
    );

    if (!rows[0]) {
      throw new BadRequestException('El método de envío no existe');
    }

    return this.normalizeShippingMethod(rows[0]);
  }

  private normalizePromotion(row: any): any {
    return {
      ...row,
      id_promocion: Number(row.id_promocion),
      valor: Number(row.valor || 0),
      descuento_maximo: row.descuento_maximo === null ? null : Number(row.descuento_maximo),
      compra_minima: Number(row.compra_minima || 0),
      uso_maximo: row.uso_maximo === null ? null : Number(row.uso_maximo),
      uso_por_usuario: row.uso_por_usuario === null ? null : Number(row.uso_por_usuario),
      usos: Number(row.usos || 0),
      activo: row.activo === true,
    };
  }

  private normalizeShippingMethod(row: any): any {
    return {
      ...row,
      id_metodo_envio: Number(row.id_metodo_envio),
      costo_base: Number(row.costo_base || 0),
      envio_gratis_desde:
        row.envio_gratis_desde === null ? null : Number(row.envio_gratis_desde),
      dias_min: Number(row.dias_min || 1),
      dias_max: Number(row.dias_max || 1),
      activo: row.activo === true,
    };
  }

  private validatePositiveInteger(value: number, message: string): void {
    if (!Number.isInteger(Number(value)) || Number(value) <= 0) {
      throw new BadRequestException(message);
    }
  }

  private validatePromotionDates(start: string, end: string): void {
    if (new Date(start).getTime() >= new Date(end).getTime()) {
      throw new BadRequestException(
        'La fecha de inicio debe ser menor a la fecha de fin',
      );
    }
  }

  private cleanText(value: string, maxLength: number): string {
    const text = this.cleanOptionalText(value, maxLength);

    if (!text) {
      throw new BadRequestException('El texto es obligatorio');
    }

    return text;
  }

  private cleanOptionalText(value: string | undefined, maxLength: number): string | null {
    const text = String(value || '')
      .trim()
      .replace(/[<>`{}\[\]\\|]/g, '')
      .replace(/\s+/g, ' ')
      .slice(0, maxLength);

    return text || null;
  }
}
