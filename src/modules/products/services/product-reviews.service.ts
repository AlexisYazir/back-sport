/* eslint-disable */
import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { CreateReviewDto } from '../dto/reviews/create-review.dto';
import { Product } from '../entities/product/product.entity';
import { Review } from '../entities/reviews/review.entity';

@Injectable()
export class ProductReviewsService {
  private readonly logger = new Logger(ProductReviewsService.name);
  private readonly blockedPatterns = [
    /<\s*script/i,
    /<\/?[a-z][\s\S]*>/i,
    /\b(select|insert|update|delete|drop|alter|truncate|exec|execute|union)\b/i,
    /(--|\/\*|\*\/|;)/,
    /\b(cmd|powershell|bash|sh|curl|wget|chmod|sudo|rm\s+-rf)\b/i,
  ];

  constructor(
    @InjectRepository(Review, 'editorConnection')
    private readonly reviewEditorRepository: Repository<Review>,
    @InjectRepository(Review, 'readerConnection')
    private readonly reviewReaderRepository: Repository<Review>,
    @InjectRepository(Product, 'readerConnection')
    private readonly productReaderRepository: Repository<Product>,
  ) {}

  private normalizeComment(comment: string): string {
    return comment.trim().replace(/\s+/g, ' ');
  }

  private validateComment(comment: string): void {
    const normalized = this.normalizeComment(comment);

    if (normalized.length < 10 || normalized.length > 800) {
      throw new BadRequestException(
        'El comentario debe tener entre 10 y 800 caracteres',
      );
    }

    if (this.blockedPatterns.some((pattern) => pattern.test(normalized))) {
      throw new BadRequestException(
        'El comentario contiene contenido no permitido',
      );
    }
  }

  private async ensureProductExists(id_producto: number): Promise<void> {
    const product = await this.productReaderRepository.findOne({
      where: { id_producto },
    });

    if (!product) {
      throw new BadRequestException('El producto no existe');
    }
  }

  private async hasDeliveredPurchase(
    id_usuario: number,
    id_producto: number,
  ): Promise<boolean> {
    const result = await this.reviewReaderRepository.query(
      `
      SELECT 1
      FROM core.orders o
      INNER JOIN core.order_items oi
        ON oi.id_orden = o.id_orden
      INNER JOIN core.product_variants pv
        ON pv.id_variante = oi.id_variante
      WHERE o.id_usuario = $1
        AND pv.id_producto = $2
        AND LOWER(TRIM(o.estado)) = 'entregado'
      LIMIT 1;
      `,
      [id_usuario, id_producto],
    );

    return result.length > 0;
  }

  async getReviewEligibility(
    id_usuario: number,
    id_producto: number,
  ): Promise<{
    canReview: boolean;
    hasDeliveredPurchase: boolean;
    hasReview: boolean;
    reason: string | null;
  }> {
    if (!Number.isInteger(id_usuario) || id_usuario <= 0) {
      throw new BadRequestException('El usuario debe ser válido');
    }

    if (!Number.isInteger(id_producto) || id_producto <= 0) {
      throw new BadRequestException('El producto debe ser válido');
    }

    await this.ensureProductExists(id_producto);

    const [hasDeliveredPurchase, existingReview] = await Promise.all([
      this.hasDeliveredPurchase(id_usuario, id_producto),
      this.reviewReaderRepository.findOne({
        where: {
          id_producto,
          id_usuario,
        },
      }),
    ]);

    const hasReview = !!existingReview;
    let reason: string | null = null;

    if (!hasDeliveredPurchase) {
      reason =
        'Solo puedes escribir reseñas de productos que ya compraste y fueron entregados';
    } else if (hasReview) {
      reason = 'Ya publicaste una reseña para este producto';
    }

    return {
      canReview: hasDeliveredPurchase && !hasReview,
      hasDeliveredPurchase,
      hasReview,
      reason,
    };
  }

  async getProductReviews(id_producto: number): Promise<any> {
    try {
      if (!Number.isInteger(id_producto) || id_producto <= 0) {
        throw new BadRequestException('El producto debe ser válido');
      }

      const reviews = await this.reviewReaderRepository.query(
        `
        SELECT
          r.id_review,
          r.id_producto,
          r.id_usuario,
          r.calificacion,
          r.comentario,
          r.fecha,
          COALESCE(NULLIF(TRIM(u.nombre), ''), 'Usuario') AS usuario
        FROM core.reviews r
        LEFT JOIN core.users u
          ON u.id_usuario = r.id_usuario
        WHERE r.id_producto = $1
        ORDER BY r.fecha DESC;
        `,
        [id_producto],
      );

      const summary = await this.reviewReaderRepository.query(
        `
        SELECT
          COUNT(*)::int AS total,
          COALESCE(ROUND(AVG(calificacion)::numeric, 1), 0)::float AS promedio
        FROM core.reviews
        WHERE id_producto = $1;
        `,
        [id_producto],
      );

      return {
        reviews,
        summary: summary[0] ?? { total: 0, promedio: 0 },
      };
    } catch (error) {
      this.logger.error('Error al consultar reseñas de producto:', error);
      throw error;
    }
  }

  async createReview(
    id_usuario: number,
    dto: CreateReviewDto,
  ): Promise<Review> {
    try {
      if (!Number.isInteger(id_usuario) || id_usuario <= 0) {
        throw new BadRequestException('El usuario debe ser válido');
      }

      this.validateComment(dto.comentario);

      const eligibility = await this.getReviewEligibility(
        id_usuario,
        dto.id_producto,
      );

      if (!eligibility.canReview) {
        throw new BadRequestException(
          eligibility.reason ?? 'No puedes publicar reseña de este producto',
        );
      }

      const review = this.reviewEditorRepository.create({
        id_producto: dto.id_producto,
        id_usuario,
        calificacion: dto.calificacion,
        comentario: this.normalizeComment(dto.comentario),
      });

      return await this.reviewEditorRepository.save(review);
    } catch (error) {
      this.logger.error('Error al crear reseña de producto:', error);

      if (error instanceof BadRequestException) {
        throw error;
      }

      if (error?.code === '23505') {
        throw new BadRequestException(
          'Ya publicaste una reseña para este producto',
        );
      }

      throw new BadRequestException('Error al crear la reseña');
    }
  }

  async getAllReviewsAdmin(): Promise<any[]> {
    return await this.reviewReaderRepository.query(`
      SELECT
        r.id_review,
        r.id_producto,
        r.id_usuario,
        r.calificacion,
        r.comentario,
        r.fecha,
        COALESCE(NULLIF(TRIM(u.nombre), ''), 'Usuario') AS usuario,
        u.email,
        p.nombre AS producto
      FROM core.reviews r
      LEFT JOIN core.users u
        ON u.id_usuario = r.id_usuario
      LEFT JOIN core.products p
        ON p.id_producto = r.id_producto
      ORDER BY r.fecha DESC;
    `);
  }
}
