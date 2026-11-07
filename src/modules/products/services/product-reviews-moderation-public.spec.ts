import type { EntityManager, Repository } from 'typeorm';
import { Product } from '../entities/product/product.entity';
import { Review } from '../entities/reviews/review.entity';
import { ProductReviewsService } from './product-reviews.service';

describe('Reseñas públicas después de añadir moderación', () => {
  test('filas y estadísticas se leen con el mismo snapshot y conservan el contrato público', async () => {
    const visible = {
      id_review: 7,
      id_usuario: 1,
      id_producto: 9,
      calificacion: 4,
      comentario: 'Comentario público sintético',
      fecha: new Date('2020-01-01T00:00:00Z'),
      usuario: 'QA',
    };
    const query = jest
      .fn<Promise<unknown>, [string, unknown[]?]>()
      .mockResolvedValueOnce([visible])
      .mockResolvedValueOnce([{ total: 1, promedio: 4 }]);
    const transaction = jest.fn(
      (
        _level: string,
        operation: (manager: EntityManager) => Promise<unknown>,
      ) => operation({ query } as unknown as EntityManager),
    );
    const outsideQuery = jest
      .fn()
      .mockRejectedValue(new Error('Lectura fuera de snapshot'));
    const reader = { manager: { transaction }, query: outsideQuery };
    const service = new ProductReviewsService(
      {} as Repository<Review>,
      reader as unknown as Repository<Review>,
      {} as Repository<Product>,
    );
    const result: unknown = await service.getProductReviews(9);
    expect(result).toEqual({
      reviews: [visible],
      summary: { total: 1, promedio: 4 },
    });
    expect(transaction.mock.calls[0][0]).toBe('REPEATABLE READ');
    expect(outsideQuery).not.toHaveBeenCalled();
  });

  test('la reseña retirada sigue contando para impedir una publicación duplicada', async () => {
    const reader = {
      query: jest.fn().mockResolvedValue([{ exists: 1 }]),
      findOne: jest
        .fn()
        .mockResolvedValue({ id_review: 7, retirada: true, revision: 1 }),
    };
    const editor = { create: jest.fn(), save: jest.fn() };
    const products = {
      findOne: jest.fn().mockResolvedValue({ id_producto: 9 }),
    };
    const service = new ProductReviewsService(
      editor as unknown as Repository<Review>,
      reader as unknown as Repository<Review>,
      products as unknown as Repository<Product>,
    );
    expect(await service.getReviewEligibility(1, 9)).toMatchObject({
      canReview: false,
      hasReview: true,
      hasDeliveredPurchase: true,
    });
    expect(editor.save).not.toHaveBeenCalled();
  });
  test('crear devuelve sólo campos públicos aunque el repositorio materialice el estado interno', async () => {
    const row = Object.assign(new Review(), {
      id_review: 7,
      id_usuario: 1,
      id_producto: 9,
      calificacion: 4,
      comentario: 'Comentario sintético válido',
      fecha: new Date('2020-01-01T00:00:00Z'),
      retirada: false,
      revision: 0,
    });
    const editor = {
      create: jest.fn().mockReturnValue(row),
      save: jest.fn().mockResolvedValue(row),
    };
    const reader = {
      query: jest.fn().mockResolvedValue([{ exists: 1 }]),
      findOne: jest.fn().mockResolvedValue(null),
    };
    const products = {
      findOne: jest.fn().mockResolvedValue({ id_producto: 9 }),
    };
    const service = new ProductReviewsService(
      editor as unknown as Repository<Review>,
      reader as unknown as Repository<Review>,
      products as unknown as Repository<Product>,
    );
    const result = await service.createReview(1, {
      id_producto: 9,
      calificacion: 4,
      comentario: row.comentario,
    });
    expect(Object.keys(result).sort()).toEqual(
      [
        'id_review',
        'id_usuario',
        'id_producto',
        'calificacion',
        'comentario',
        'fecha',
      ].sort(),
    );
    expect(result).not.toHaveProperty('retirada');
    expect(result).not.toHaveProperty('revision');
  });
});
