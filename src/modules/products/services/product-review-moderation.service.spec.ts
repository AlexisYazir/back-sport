import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  ValidationPipe,
} from '@nestjs/common';
import type { DataSource, EntityManager } from 'typeorm';
import {
  ModerateReviewDto,
  ReviewReportsQueryDto,
} from '../dto/reviews/moderation.dto';
import {
  parseReviewReportSubject,
  ProductReviewModerationService,
} from './product-review-moderation.service';

const subject = 'Reporte de reseña #7 · producto #9';
const review = { id_review: 7, id_producto: 9, retirada: false, revision: 0 };
const decision = (): ModerateReviewDto => ({
  accion: 'retirar',
  motivo: ' Contenido revisado por Administración. ',
  revision_esperada: 0,
  id_mensaje: 11,
});
function fixture(
  options: {
    actorMissing?: boolean;
    changed?: boolean;
    wrongReport?: boolean;
    withdrawn?: boolean;
    auditFailure?: boolean;
    missingReview?: boolean;
  } = {},
) {
  const writes: { sql: string; params: unknown[] }[] = [];
  const query = jest.fn<Promise<unknown>, [string, unknown[]?]>(
    (sql, params = []) =>
      Promise.resolve().then(() => {
        if (sql.startsWith('SELECT id_usuario'))
          return options.actorMissing ? [] : [{ id_usuario: 3 }];
        if (sql.includes('FOR UPDATE') && sql.includes('core.reviews'))
          return options.missingReview
            ? []
            : [
                {
                  ...review,
                  revision: options.changed ? 1 : 0,
                  retirada: options.withdrawn ?? false,
                },
              ];
        if (sql.includes('FOR UPDATE') && sql.includes('contact_messages'))
          return [
            {
              asunto: options.wrongReport
                ? 'Reporte de reseña #8 · producto #9'
                : subject,
            },
          ];
        writes.push({ sql, params });
        if (options.auditFailure && sql.includes('INSERT INTO'))
          throw new Error('synthetic audit failure');
        return [];
      }),
  );
  const transaction = jest.fn(
    async (operation: (manager: EntityManager) => Promise<unknown>) =>
      operation({ query } as unknown as EntityManager),
  );
  const source = { transaction, query: jest.fn() };
  const service = new ProductReviewModerationService(
    source as unknown as DataSource,
  );
  const detail = {
    review: {
      ...review,
      fecha: '2020-01-01T00:00:00.000Z',
      usuario: 'QA',
      email: null,
      producto: null,
      id_usuario: 1,
      calificacion: 4,
      comentario: 'Contenido sintético',
    },
    reports: [],
    history: [],
  };
  const detailSpy = jest
    .spyOn(service, 'getReviewModeration')
    .mockResolvedValue(detail);
  return { service, query, transaction, source, writes, detailSpy };
}

describe('Moderación: validación y decisiones del servidor', () => {
  test('cola y detalle usan una lectura transaccional completa, sin mezclar otra conexión', async () => {
    const date = new Date('2020-01-01T00:00:00Z');
    const report = {
      id_mensaje: 11,
      nombre: 'QA',
      email: 'qa@example.test',
      asunto: subject,
      mensaje: 'Reporte sintético',
      created_at: date,
      leido: false,
      respondido: false,
      referencia_valida: true,
      atendido: false,
    };
    const query = jest
      .fn<Promise<unknown>, [string, unknown[]?]>()
      .mockResolvedValueOnce([{ total: 1 }])
      .mockResolvedValueOnce([report])
      .mockResolvedValueOnce([
        {
          ...review,
          fecha: date,
          usuario: 'QA',
          email: null,
          producto: 'Producto QA',
          id_usuario: 1,
          calificacion: 4,
          comentario: 'Comentario sintético',
        },
      ])
      .mockResolvedValueOnce([report])
      .mockResolvedValueOnce([]);
    const transaction = jest.fn(
      (
        _level: string,
        operation: (manager: EntityManager) => Promise<unknown>,
      ) => operation({ query } as unknown as EntityManager),
    );
    const outsideQuery = jest
      .fn()
      .mockRejectedValue(new Error('Otra conexión no comparte el snapshot'));
    const service = new ProductReviewModerationService({
      transaction,
      query: outsideQuery,
    } as unknown as DataSource);
    const page = await service.getReviewReports(new ReviewReportsQueryDto());
    expect(page.total).toBe(page.items.length);
    expect(page.items[0]).toMatchObject({
      id_review: 7,
      id_producto: 9,
      referencia_valida: true,
      estado_atencion: 'pendiente',
      created_at: date.toISOString(),
    });
    const detail = await service.getReviewModeration(7);
    expect(detail.review).toMatchObject({ retirada: false, revision: 0 });
    expect(detail.reports).toEqual(page.items);
    expect(detail.history).toEqual([]);
    const contactReads = query.mock.calls
      .map(([sql]) => sql)
      .filter((sql) => sql.includes('contact_messages'));
    expect(contactReads.length).toBeGreaterThan(0);
    expect(
      contactReads.every((sql) => sql.includes('FROM core.contact_messages')),
    ).toBe(true);
    expect(contactReads.join('\n')).not.toContain('public.contact_messages');
    expect(transaction.mock.calls.map(([level]) => level)).toEqual([
      'REPEATABLE READ',
      'REPEATABLE READ',
    ]);
    expect(outsideQuery).not.toHaveBeenCalled();
  });

  test('reconoce sólo la referencia completa vigente y no acepta enteros fuera de PostgreSQL', () => {
    expect(parseReviewReportSubject(subject)).toEqual({
      reviewId: 7,
      productId: 9,
    });
    for (const value of [
      null,
      '',
      ' ' + subject,
      subject + ' extra',
      subject.replace('#7', '#07'),
      subject.replace('#7', '#-7'),
      subject.replace('#7', '#2147483648'),
    ])
      expect(parseReviewReportSubject(value)).toBeNull();
  });

  test('el pipe rechaza actor, fechas, acciones y motivos inválidos; convierte sólo filtros declarados', async () => {
    const pipe = new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    });
    const query: unknown = await pipe.transform(
      { page: '2', limit: '10' },
      { type: 'query', metatype: ReviewReportsQueryDto },
    );
    expect(query).toEqual({ estado: 'pendiente', page: 2, limit: 10 });
    for (const extra of [
      { id_administrador: 99 },
      { fecha: '2020-01-01' },
      { accion: 'eliminar' },
      { motivo: '   ' },
      { motivo: 'x'.repeat(1001) },
      { revision_esperada: -1 },
      { id_mensaje: 0 },
    ])
      await expect(
        pipe.transform(
          { ...decision(), ...extra },
          { type: 'body', metatype: ModerateReviewDto },
        ),
      ).rejects.toBeInstanceOf(BadRequestException);
    for (const extra of [
      { estado: 'otro' },
      { page: '1.5' },
      { page: 0 },
      { limit: 101 },
      { actor: 3 },
    ])
      await expect(
        pipe.transform(extra, {
          type: 'query',
          metatype: ReviewReportsQueryDto,
        }),
      ).rejects.toBeInstanceOf(BadRequestException);
  });

  test('un actor que ya no es Admin activo no provoca cambios', async () => {
    const f = fixture({ actorMissing: true });
    await expect(
      f.service.moderateReview(7, 3, decision()),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(f.query.mock.calls[0][0]).toContain('rol=3 AND activo=1 FOR SHARE');
    expect(f.writes).toEqual([]);
    expect(f.detailSpy).not.toHaveBeenCalled();
  });

  test('una revisión obsoleta o un folio ajeno fallan antes de escribir', async () => {
    const stale = fixture({ changed: true });
    await expect(
      stale.service.moderateReview(7, 3, decision()),
    ).rejects.toBeInstanceOf(ConflictException);
    expect(stale.writes).toEqual([]);
    const other = fixture({ wrongReport: true });
    await expect(
      other.service.moderateReview(7, 3, decision()),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(other.writes).toEqual([]);
  });

  test('registrar conservar mantiene una retirada, usa actor servidor y no afirma respuesta enviada', async () => {
    const f = fixture({ withdrawn: true });
    await f.service.moderateReview(7, 3, {
      ...decision(),
      accion: 'conservar',
    });
    expect(f.writes[0].params).toEqual([true, 1, 7]);
    expect(f.writes[1].params).toEqual([
      7,
      11,
      'conservar',
      'Contenido revisado por Administración.',
      3,
      true,
      true,
      1,
    ]);
    expect(f.writes[2].sql).toContain('leido=true');
    expect(f.writes[2].sql).toContain('UPDATE core.contact_messages');
    expect(
      f.query.mock.calls.find(([sql]) => sql.startsWith('SELECT asunto'))?.[0],
    ).toContain('FROM core.contact_messages');
    expect(f.writes[2].sql).not.toContain('respondido');
    expect(f.detailSpy).toHaveBeenCalledWith(7);
  });

  test.each([
    ['retirar', false, true],
    ['restaurar', true, false],
  ] as const)(
    '%s registra estado anterior/nuevo y revisión siguiente',
    async (accion, previous, next) => {
      const f = fixture({ withdrawn: previous });
      await f.service.moderateReview(7, 3, {
        ...decision(),
        accion,
        id_mensaje: undefined,
      });
      expect(f.writes[0].params).toEqual([next, 1, 7]);
      expect(f.writes[1].params.slice(4)).toEqual([3, previous, next, 1]);
      expect(f.writes).toHaveLength(2);
    },
  );

  test('fallar el append de auditoría rechaza la transacción y no marca el mensaje ni responde éxito', async () => {
    const f = fixture({ auditFailure: true });
    await expect(f.service.moderateReview(7, 3, decision())).rejects.toThrow(
      'synthetic audit failure',
    );
    expect(f.writes).toHaveLength(2);
    expect(f.detailSpy).not.toHaveBeenCalled();
  });

  test('reseña inexistente y datos inválidos no generan escrituras', async () => {
    const missing = fixture({ missingReview: true });
    await expect(
      missing.service.moderateReview(7, 3, decision()),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(missing.writes).toEqual([]);
    const invalid = fixture();
    await expect(
      invalid.service.moderateReview(7, 3, { ...decision(), motivo: '' }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(invalid.transaction).not.toHaveBeenCalled();
  });
});
