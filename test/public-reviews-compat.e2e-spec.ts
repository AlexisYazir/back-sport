import type { Server } from 'node:http';
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { type INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthGuard } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { DataSource, type Repository } from 'typeorm';
import { ReviewModeration1793740000000 } from '../src/database/migrations/1793740000000-ReviewModeration';
import { Product } from '../src/modules/products/entities/product/product.entity';
import { Review } from '../src/modules/products/entities/reviews/review.entity';
import { ProductsController } from '../src/modules/products/products.controller';
import { ProductsService } from '../src/modules/products/products.service';
import { ProductReviewsService } from '../src/modules/products/services/product-reviews.service';
import { ActiveAdminGuard } from '../src/services/auth/active-admin.guard';
import { RolesGuard } from '../src/services/auth/roles.guard';

interface PublicPage {
  reviews: (Record<string, unknown> & { id_review: number })[];
  summary: { total: number; promedio: number };
}

const publicPage = (response: request.Response): PublicPage =>
  response.body as PublicPage;

// Opt-in y conexión exclusivamente a un PostgreSQL local efímero y vacío.
function databaseUrl(): URL {
  const url = new URL(process.env.PUBLIC_REVIEWS_QA_URL ?? 'invalid:');
  if (
    process.env.PUBLIC_REVIEWS_QA !== 'true' ||
    url.protocol !== 'postgres:' ||
    url.hostname !== '127.0.0.1' ||
    !/^\d+$/.test(url.port) ||
    Number(url.port) < 1024 ||
    url.pathname !== '/sportcenter_moderation_qa' ||
    url.username !== 'qa_admin' ||
    url.search ||
    url.hash
  )
    throw new Error('PUBLIC_REVIEWS_LOCAL_QA_REQUIRED');
  return url;
}

describe('Reseñas públicas: HTTP y PostgreSQL antes y después de moderación', () => {
  let admin: DataSource;
  let reader: DataSource;
  let app: INestApplication<Server>;
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    const url = databaseUrl();
    admin = await new DataSource({
      type: 'postgres',
      url: url.href,
      synchronize: false,
      schema: 'core',
      migrations: [ReviewModeration1793740000000],
    }).initialize();
    expect(
      await admin.query(
        "SELECT current_database() AS db, current_user AS role, to_regnamespace('core') AS schema",
      ),
    ).toEqual([
      { db: 'sportcenter_moderation_qa', role: 'qa_admin', schema: null },
    ]);
    await admin.query(
      readFileSync(path.join(__dirname, 'moderation/schema.sql'), 'utf8'),
    );
    url.username = 'qa_reader';
    url.password = 'qa-reader-local';
    reader = await new DataSource({
      type: 'postgres',
      url: url.href,
      synchronize: false,
      entities: [Review],
    }).initialize();
    const service = new ProductReviewsService(
      reader.getRepository(Review),
      reader.getRepository(Review),
      {} as Repository<Product>,
    );
    // Controlador y servicio de reseñas reales; los demás servicios no intervienen.
    // Las rutas protegidas quedan denegadas en esta aplicación de prueba.
    const deny = { canActivate: () => false };
    const module = await Test.createTestingModule({
      controllers: [ProductsController],
      providers: [
        ConfigService,
        {
          provide: ProductsService,
          useValue: {
            getProductReviews: (id: number) => service.getProductReviews(id),
          },
        },
      ],
    })
      .overrideGuard(AuthGuard('jwt'))
      .useValue(deny)
      .overrideGuard(RolesGuard)
      .useValue(deny)
      .overrideGuard(ActiveAdminGuard)
      .useValue(deny)
      .compile();
    app = module.createNestApplication();
    app.useLogger(false);
    await app.init();
  });

  afterAll(async () => {
    if (app) await app.close();
    if (reader?.isInitialized) await reader.destroy();
    if (admin?.isInitialized) await admin.destroy();
  });

  test('reproduce el SQLSTATE 42703 de la consulta anterior sin retirada', async () => {
    await expect(
      reader.query(
        'SELECT r.id_review FROM core.reviews r WHERE r.retirada = false',
      ),
    ).rejects.toMatchObject({ code: '42703' });
  });

  test('GET conserva las reseñas reales y el promedio en el esquema anterior', async () => {
    const body = publicPage(
      await http().get('/products/reviews/product/320001').expect(200),
    );
    expect(body.summary).toEqual({ total: 2, promedio: 3 });
    expect(body.reviews.map((row) => row.id_review).sort()).toEqual([
      330001, 330002,
    ]);
    expect(Object.keys(body.reviews[0]).sort()).toEqual(
      [
        'id_review',
        'id_producto',
        'id_usuario',
        'calificacion',
        'comentario',
        'fecha',
        'usuario',
      ].sort(),
    );
  });

  test('un producto sin reseñas responde 200 con lista y estadísticas vacías', async () => {
    const body = publicPage(
      await http().get('/products/reviews/product/320099').expect(200),
    );
    expect(body).toEqual({ reviews: [], summary: { total: 0, promedio: 0 } });
  });

  test('los identificadores inválidos siguen rechazándose', async () => {
    await http().get('/products/reviews/product/incorrecto').expect(400);
    await http().get('/products/reviews/product/0').expect(400);
  });

  test('el lector no obtiene permisos de escritura', async () => {
    await expect(
      reader.query(
        'UPDATE core.reviews SET calificacion = 5 WHERE id_review = 330002',
      ),
    ).rejects.toMatchObject({ code: '42501' });
  });

  test('la migración real conserva el contrato público y el promedio', async () => {
    await admin.runMigrations({ transaction: 'all' });
    const body = publicPage(
      await http().get('/products/reviews/product/320001').expect(200),
    );
    expect(body.summary).toEqual({ total: 2, promedio: 3 });
    expect(body.reviews).toHaveLength(2);
    expect(body.reviews[0]).not.toHaveProperty('retirada');
    expect(body.reviews[0]).not.toHaveProperty('revision');
  });

  async function decide(id: number, hidden: boolean, revision: number) {
    await admin.transaction(async (manager) => {
      await manager.query(
        `INSERT INTO core.review_moderation_events
        (id_review,accion,motivo,id_administrador,retirada_anterior,retirada_nueva,revision)
        VALUES ($1,$2,'QA local',310003,$3,$4,$5)`,
        [id, hidden ? 'retirar' : 'restaurar', !hidden, hidden, revision],
      );
      await manager.query(
        'UPDATE core.reviews SET retirada=$2, revision=$3 WHERE id_review=$1',
        [id, hidden, revision],
      );
    });
  }

  test('una reseña retirada queda fuera tanto del listado como del promedio', async () => {
    await decide(330002, true, 1);
    const body = publicPage(
      await http().get('/products/reviews/product/320001').expect(200),
    );
    expect(body.summary).toEqual({ total: 1, promedio: 5 });
    expect(body.reviews.map((row) => row.id_review)).toEqual([330001]);
  });

  test('si todas están retiradas no se exponen reseñas ni calificaciones', async () => {
    await decide(330001, true, 1);
    const body = publicPage(
      await http().get('/products/reviews/product/320001').expect(200),
    );
    expect(body).toEqual({ reviews: [], summary: { total: 0, promedio: 0 } });
  });

  test('una restauración vuelve a reflejarse sin mezclar productos', async () => {
    await decide(330002, false, 2);
    const body = publicPage(
      await http().get('/products/reviews/product/320001').expect(200),
    );
    expect(body.summary).toEqual({ total: 1, promedio: 1 });
    expect(body.reviews.map((row) => row.id_review)).toEqual([330002]);
  });
});
