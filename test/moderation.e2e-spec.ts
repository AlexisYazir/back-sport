import type { Server } from 'node:http';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { getDataSourceToken, getRepositoryToken } from '@nestjs/typeorm';
import * as jwt from 'jsonwebtoken';
import request from 'supertest';
import { DataSource } from 'typeorm';
import { ReviewModeration1793740000000 } from '../src/database/migrations/1793740000000-ReviewModeration';
import { CompanyController } from '../src/modules/company/company.controller';
import { CompanyService } from '../src/modules/company/company.service';
import { CompanyInfo } from '../src/modules/company/entities/company-info.entity';
import { ContactMessage } from '../src/modules/company/entities/contact-message.entity';
import { Faq } from '../src/modules/company/entities/faq.entity';
import { Product } from '../src/modules/products/entities/product/product.entity';
import { Review } from '../src/modules/products/entities/reviews/review.entity';
import { ProductsController } from '../src/modules/products/products.controller';
import { ProductsService } from '../src/modules/products/products.service';
import { ProductBrandCategoryService } from '../src/modules/products/services/product-brand-category.service';
import { ProductCartService } from '../src/modules/products/services/product-cart.service';
import { ProductCatalogService } from '../src/modules/products/services/product-catalog.service';
import { ProductCheckoutService } from '../src/modules/products/services/product-checkout.service';
import { ProductInventoryService } from '../src/modules/products/services/product-inventory.service';
import { ProductOrdersService } from '../src/modules/products/services/product-orders.service';
import { ProductPromotionsService } from '../src/modules/products/services/product-promotions.service';
import { ProductReviewModerationService } from '../src/modules/products/services/product-review-moderation.service';
import { ProductReviewsService } from '../src/modules/products/services/product-reviews.service';
import { UserSession } from '../src/modules/users/entities/user-session.entity';
import { User } from '../src/modules/users/entities/user.entity';
import { UserAccountService } from '../src/modules/users/services/user-account.service';
import { UserAdminService } from '../src/modules/users/services/user-admin.service';
import { UserGoogleAuthService } from '../src/modules/users/services/user-google-auth.service';
import { UserPasswordRecoveryService } from '../src/modules/users/services/user-password-recovery.service';
import { UserSessionService } from '../src/modules/users/services/user-session.service';
import { UsersService } from '../src/modules/users/users.service';
import { ActiveAdminGuard } from '../src/services/auth/active-admin.guard';
import { JwtStrategy } from '../src/services/auth/jwt.strategy';
import { RolesGuard } from '../src/services/auth/roles.guard';

interface AdminReview {
  id_review: number;
  retirada: boolean;
  revision: number;
  comentario: string;
}
interface Event {
  id_evento: number;
  id_review: number;
  id_mensaje: number | null;
  id_administrador: number;
  accion: string;
  motivo: string;
  revision: number;
  retirada_anterior: boolean;
  retirada_nueva: boolean;
}
interface ModerationDetail {
  review: AdminReview;
  reports: Report[];
  history: Event[];
}
interface Report {
  id_mensaje: number;
  referencia_valida: boolean;
  estado_atencion: string;
  leido: boolean;
  respondido: boolean;
}
interface ReportPage {
  items: Report[];
  total: number;
  page: number;
  limit: number;
}
interface PublicPage {
  reviews: Record<string, unknown>[];
  summary: { total: number; promedio: number };
}

const BASE = '/products/reviews/admin';
const SECRET = 'moderation-qa-not-a-production-secret';
const entities = [
  User,
  UserSession,
  Product,
  Review,
  ContactMessage,
  CompanyInfo,
  Faq,
];
const responseBody = <T>(response: request.Response): T => response.body as T;

// This file refuses ordinary environments rather than silently skipping a DB test.
function connection(role: 'ADMIN' | 'EDITOR' | 'READER'): string {
  if (
    process.env.MODERATION_QA !== 'true' ||
    process.env.JWT_SECRET !== SECRET
  ) {
    throw new Error('MODERATION_QA_OPT_IN_REQUIRED');
  }
  if (
    Object.keys(process.env).some((key) =>
      /MERCADO_PAGO|SMTP|MAIL_PASSWORD|EMAIL_PASS|SENDGRID|RESEND|MAILGUN/i.test(
        key,
      ),
    )
  ) {
    throw new Error('MODERATION_QA_PROVIDERS_FORBIDDEN');
  }
  const value = process.env['DATABASE_URL_' + role] ?? '';
  const url = new URL(value);
  const loopback =
    url.hostname === '127.0.0.1' &&
    /^\d+$/.test(process.env.MODERATION_QA_PORT ?? '') &&
    url.port === process.env.MODERATION_QA_PORT &&
    Number(url.port) >= 1024;
  if (
    url.protocol !== 'postgres:' ||
    !loopback ||
    url.pathname !== '/sportcenter_moderation_qa' ||
    url.username !== 'qa_' + role.toLowerCase()
  ) {
    throw new Error('MODERATION_QA_DATABASE_REQUIRED');
  }
  return value;
}

describe('Moderation: real isolated PostgreSQL and HTTP', () => {
  let app: INestApplication<Server> | undefined;
  let admin: DataSource;
  let editor: DataSource;
  let reader: DataSource;
  let moderation: ProductReviewModerationService;
  let reportA: number;
  let reportB: number;
  let rollbackReport: number;
  let originalContact: ContactMessage;

  const token = (
    role: number,
    userId = 310000 + role,
    session = role,
  ): string =>
    jwt.sign(
      {
        id_usuario: userId,
        rol: role,
        email: 'synthetic@qa.invalid',
        nombre: 'QA',
        sessionId:
          '10000000-0000-4000-8000-' + String(session).padStart(12, '0'),
      },
      SECRET,
      { expiresIn: '10m' },
    );
  const http = () => request(app!.getHttpServer());
  const adminGet = (path: string) =>
    http().get(path).auth(token(3), { type: 'bearer' });
  const decision = (
    id: number,
    revision: number,
    accion: string,
    extra: Record<string, unknown> = {},
  ) =>
    http()
      .post(`${BASE}/${id}/moderation`)
      .auth(token(3), { type: 'bearer' })
      .send({
        accion,
        revision_esperada: revision,
        motivo: 'Decision sintetica QA autorizada',
        ...extra,
      });
  const contact = async (review: number, product: number): Promise<number> => {
    const result = await http()
      .post('/company/contact')
      .send({
        nombre: 'Cliente QA',
        email: 'moderation-report@qa.invalid',
        asunto: `Reporte de reseña #${review} · producto #${product}`,
        mensaje: `Reseña #${review} del producto #${product}\nMotivo: Reporte sintetico de moderacion QA.`,
      })
      .expect(201);
    const id = responseBody<{ id_mensaje: number }>(result).id_mensaje;
    expect(Number.isSafeInteger(id) && id > 0).toBe(true);
    return id;
  };
  const detail = async (id: number): Promise<ModerationDetail> =>
    responseBody<ModerationDetail>(
      await adminGet(`${BASE}/${id}/moderation`).expect(200),
    );

  beforeAll(async () => {
    admin = new DataSource({
      type: 'postgres',
      url: connection('ADMIN'),
      entities,
      migrations: [ReviewModeration1793740000000],
      migrationsTableName: 'moderation_qa_migrations',
      synchronize: false,
      logging: false,
    });
    editor = new DataSource({
      type: 'postgres',
      url: connection('EDITOR'),
      entities,
      synchronize: false,
      logging: false,
    });
    reader = new DataSource({
      type: 'postgres',
      url: connection('READER'),
      entities,
      synchronize: false,
      logging: false,
    });
    await admin.initialize();
    const identity = await admin.query<
      Array<{ database: string; role: string }>
    >('SELECT current_database() AS database,current_user AS role');
    expect(identity).toEqual([
      { database: 'sportcenter_moderation_qa', role: 'qa_admin' },
    ]);
    await admin.runMigrations({ transaction: 'all' });
    await editor.initialize();
    await reader.initialize();

    const unused = [
      ProductCatalogService,
      ProductInventoryService,
      ProductBrandCategoryService,
      ProductOrdersService,
      ProductCartService,
      ProductCheckoutService,
      ProductPromotionsService,
      UserAccountService,
      UserAdminService,
      UserGoogleAuthService,
      UserPasswordRecoveryService,
    ];
    const repositories = [
      { name: 'editorConnection', source: editor },
      { name: 'readerConnection', source: reader },
    ].flatMap(({ name, source }) =>
      entities.map((entity) => ({
        provide: getRepositoryToken(entity, name),
        useValue: source.getRepository(entity),
      })),
    );
    const module = await Test.createTestingModule({
      controllers: [ProductsController, CompanyController],
      providers: [
        ProductsService,
        CompanyService,
        ProductReviewsService,
        ProductReviewModerationService,
        UsersService,
        UserSessionService,
        JwtStrategy,
        RolesGuard,
        ActiveAdminGuard,
        {
          provide: ConfigService,
          useValue: new ConfigService({ JWT_SECRET: SECRET }),
        },
        { provide: getDataSourceToken('editorConnection'), useValue: editor },
        { provide: getDataSourceToken('readerConnection'), useValue: reader },
        ...repositories,
        ...unused.map((provide) => ({ provide, useValue: Object.freeze({}) })),
      ],
    }).compile();
    moderation = module.get(ProductReviewModerationService);
    app = module.createNestApplication<INestApplication<Server>>();
    app.useLogger(false);
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    await app.init();
  }, 60000);

  afterAll(async () => {
    if (app) await app.close();
    for (const source of [reader, editor, admin])
      if (source?.isInitialized) await source.destroy();
  });

  it('M01 migration up/down preserves existing rows and grants no PUBLIC access', async () => {
    const rows = await admin.query<
      Array<{ retirada: boolean; revision: number }>
    >('SELECT retirada,revision FROM core.reviews ORDER BY id_review');
    expect(rows).toHaveLength(5);
    expect(rows.every((row) => !row.retirada && row.revision === 0)).toBe(true);
    const grants = await admin.query<
      Array<{ total: number }>
    >(`SELECT count(*)::int AS total FROM pg_class c,
      LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
      WHERE c.oid='core.review_moderation_events'::regclass AND a.grantee=0`);
    expect(grants[0].total).toBe(0);
    await admin.undoLastMigration({ transaction: 'all' });
    const columns = await admin.query<
      Array<{ total: number }>
    >(`SELECT count(*)::int AS total FROM information_schema.columns
      WHERE table_schema='core' AND table_name='reviews' AND column_name IN ('retirada','revision')`);
    expect(columns[0].total).toBe(0);
    expect(
      await admin.query<Array<{ total: number }>>(
        'SELECT count(*)::int AS total FROM core.reviews',
      ),
    ).toEqual([{ total: 5 }]);
    await admin.runMigrations({ transaction: 'all' });
  });

  it('M02 rejects guests on all moderation and private contact endpoints', async () => {
    for (const path of [
      `${BASE}/reports`,
      `${BASE}/330001/moderation`,
      '/company/contact',
      '/company/contact/1',
    ]) {
      await http().get(path).expect(401);
    }
    await http().post(`${BASE}/330001/moderation`).send({}).expect(401);
    await http().patch('/company/contact/1').send({ leido: true }).expect(401);
    await http().delete('/company/contact/1').expect(401);
  });

  it.each([1, 2])(
    'M03 rejects actual role %i before accessing private reports or decisions',
    async (role) => {
      for (const path of [
        `${BASE}/reports`,
        `${BASE}/330001/moderation`,
        '/company/contact',
      ]) {
        await http()
          .get(path)
          .auth(token(role), { type: 'bearer' })
          .expect(403);
      }
      await http()
        .post(`${BASE}/330001/moderation`)
        .auth(token(role), { type: 'bearer' })
        .send({})
        .expect(403);
      await http()
        .patch('/company/contact/1')
        .auth(token(role), { type: 'bearer' })
        .send({ leido: true })
        .expect(403);
      await http()
        .delete('/company/contact/1')
        .auth(token(role), { type: 'bearer' })
        .expect(403);
    },
  );

  it('M04 rejects expired or revoked sessions, stale administrator roles and unknown actors', async () => {
    const expired = jwt.sign(
      {
        id_usuario: 310003,
        rol: 3,
        sessionId: '10000000-0000-4000-8000-000000000003',
      },
      SECRET,
      { expiresIn: -1 },
    );
    await http()
      .get(`${BASE}/reports`)
      .auth(expired, { type: 'bearer' })
      .expect(401);
    await http()
      .get(`${BASE}/reports`)
      .auth('invalid.token', { type: 'bearer' })
      .expect(401);
    for (const user of [310001, 310004, 319999]) {
      await http()
        .get(`${BASE}/reports`)
        .auth(token(3, user, 3), { type: 'bearer' })
        .expect(403);
    }
    await admin.query(
      "UPDATE core.user_sessions SET revocada_en=CURRENT_TIMESTAMP WHERE id_sesion='10000000-0000-4000-8000-000000000005'",
    );
    await http()
      .get(`${BASE}/reports`)
      .auth(token(3, 310005, 5), { type: 'bearer' })
      .expect(401);
    await expect(
      moderation.moderateReview(330001, 319999, {
        accion: 'retirar',
        motivo: 'QA actor inexistente',
        revision_esperada: 0,
      }),
    ).rejects.toMatchObject({ status: 403 });
  });

  it('M05 receives real reports and distinguishes a mismatched product reference', async () => {
    reportA = await contact(330001, 320001);
    reportB = await contact(330003, 320002);
    const mismatch = await contact(330001, 320002);
    rollbackReport = await contact(330005, 320002);
    originalContact = (
      await admin.query<ContactMessage[]>(
        'SELECT * FROM public.contact_messages WHERE id_mensaje=$1',
        [reportA],
      )
    )[0];
    const page = responseBody<ReportPage>(
      await adminGet(`${BASE}/reports`).expect(200),
    );
    expect(page.page).toBe(1);
    expect(page.limit).toBe(20);
    expect(
      page.items.find((item) => item.id_mensaje === reportA),
    ).toMatchObject({
      referencia_valida: true,
      estado_atencion: 'pendiente',
      leido: false,
      respondido: false,
    });
    expect(
      page.items.find((item) => item.id_mensaje === mismatch),
    ).toMatchObject({ referencia_valida: false });
    await adminGet(`${BASE}/reports?limit=1&page=2&estado=todos`).expect(200);
  });

  it('M06 validates query/body, rejects fake actor keys and never writes on a mismatched folio', async () => {
    for (const query of [
      'limit=101',
      'limit=0',
      'page=0',
      'estado=invalid',
      'page=abc',
      'unknown=true',
    ]) {
      await adminGet(`${BASE}/reports?${query}`).expect(400);
    }
    for (const extra of [
      { id_administrador: 310005 },
      { retirada: true },
      { revision_esperada: -1 },
      { revision_esperada: '0' },
      { motivo: ' ' },
      { motivo: 'x'.repeat(1001) },
      { accion: 'borrar' },
    ]) {
      await decision(330001, 0, 'retirar', extra).expect(400);
    }
    await decision(330001, 0, 'retirar', { id_mensaje: reportB }).expect(400);
    const current = await detail(330001);
    expect(current.review).toMatchObject({ retirada: false, revision: 0 });
    expect(current.history).toEqual([]);
    expect(
      (
        await admin.query<ContactMessage[]>(
          'SELECT * FROM public.contact_messages WHERE id_mensaje=$1',
          [reportA],
        )
      )[0],
    ).toEqual(originalContact);
  });

  it('M07 preserves, withdraws and restores with immutable audit and correct public aggregates', async () => {
    const getPublic = async () =>
      responseBody<PublicPage>(
        await http().get('/products/reviews/product/320001').expect(200),
      );
    expect((await getPublic()).summary).toEqual({ total: 2, promedio: 3 });
    let result = responseBody<ModerationDetail>(
      await decision(330001, 0, 'conservar', { id_mensaje: reportA }).expect(
        201,
      ),
    );
    expect(result.review).toMatchObject({ retirada: false, revision: 1 });
    result = responseBody<ModerationDetail>(
      await decision(330001, 1, 'retirar', { id_mensaje: reportA }).expect(201),
    );
    expect(result.review).toMatchObject({
      retirada: true,
      revision: 2,
      comentario: 'Resena sintetica QA uno',
    });
    const withdrawn = await getPublic();
    expect(withdrawn.summary).toEqual({ total: 1, promedio: 1 });
    expect(withdrawn.reviews.map((row) => row.id_review)).toEqual([330002]);
    for (const row of withdrawn.reviews)
      expect(
        Object.keys(row).some((key) =>
          /retirada|revision|history|moderacion|email/.test(key),
        ),
      ).toBe(false);
    result = responseBody<ModerationDetail>(
      await decision(330001, 2, 'conservar', { id_mensaje: reportA }).expect(
        201,
      ),
    );
    expect(result.review).toMatchObject({ retirada: true, revision: 3 });
    expect((await getPublic()).summary.total).toBe(1);
    result = responseBody<ModerationDetail>(
      await decision(330001, 3, 'restaurar', { id_mensaje: reportA }).expect(
        201,
      ),
    );
    expect(result.review).toMatchObject({ retirada: false, revision: 4 });
    expect((await getPublic()).summary).toEqual({ total: 2, promedio: 3 });
    expect(result.history).toHaveLength(4);
    expect(
      result.history.every(
        (event) =>
          event.id_administrador === 310003 && event.id_mensaje === reportA,
      ),
    ).toBe(true);
    expect(
      result.history.map((event) => event.revision).sort((a, b) => a - b),
    ).toEqual([1, 2, 3, 4]);
    const contactRow = (
      await admin.query<ContactMessage[]>(
        'SELECT * FROM public.contact_messages WHERE id_mensaje=$1',
        [reportA],
      )
    )[0];
    expect(contactRow).toMatchObject({
      nombre: originalContact.nombre,
      email: originalContact.email,
      asunto: originalContact.asunto,
      mensaje: originalContact.mensaje,
      respondido: false,
      id_usuario_responde: null,
      leido: true,
    });
    const attended = responseBody<ReportPage>(
      await adminGet(`${BASE}/reports?estado=atendido`).expect(200),
    );
    expect(attended.items.some((row) => row.id_mensaje === reportA)).toBe(true);
  });

  it('M08 a withdrawn existing review remains ineligible for duplicate publication', async () => {
    await decision(330001, 4, 'retirar').expect(201);
    const eligibility = await http()
      .get('/products/reviews/product/320001/eligibility')
      .auth(token(1), { type: 'bearer' })
      .expect(200);
    expect(responseBody<Record<string, unknown>>(eligibility)).toMatchObject({
      hasDeliveredPurchase: true,
      hasReview: true,
      canReview: false,
    });
    await http()
      .post('/products/reviews')
      .auth(token(1), { type: 'bearer' })
      .send({
        id_producto: 320001,
        calificacion: 4,
        comentario: 'Intento duplicado sintetico QA',
      })
      .expect(400);
    expect(
      (
        await admin.query<Array<{ total: number }>>(
          'SELECT count(*)::int AS total FROM core.reviews WHERE id_usuario=310001 AND id_producto=320001',
        )
      )[0].total,
    ).toBe(1);
  });

  it('M09 row lock and expected revision accept one simultaneous submit and reject replay', async () => {
    const results = await Promise.all([
      decision(330004, 0, 'retirar'),
      decision(330004, 0, 'conservar'),
    ]);
    expect(results.map((result) => result.status).sort()).toEqual([201, 409]);
    const current = await detail(330004);
    expect(current.review.revision).toBe(1);
    expect(current.history).toHaveLength(1);
    await decision(330004, 0, 'restaurar').expect(409);
    expect((await detail(330004)).history).toHaveLength(1);
  });

  it('M10 audit failure rolls back review visibility, revision, report flags and history together', async () => {
    const auditSequence = async () =>
      (
        await admin.query<Array<{ value: string; is_called: boolean }>>(
          'SELECT last_value::text AS value,is_called FROM core.review_moderation_events_id_evento_seq',
        )
      )[0];
    const beforeSequence = await auditSequence();
    await admin.query(`CREATE FUNCTION core.qa_moderation_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.id_review=330005 THEN RAISE EXCEPTION 'QA_FORCED_AUDIT_FAILURE'; END IF; RETURN NEW; END $$;
      CREATE TRIGGER qa_moderation_fail_audit BEFORE INSERT ON core.review_moderation_events
      FOR EACH ROW EXECUTE FUNCTION core.qa_moderation_fail_audit()`);
    try {
      await decision(330005, 0, 'retirar', {
        id_mensaje: rollbackReport,
      }).expect(500);
      const afterSequence = await auditSequence();
      expect(afterSequence.is_called).toBe(true);
      expect(
        !beforeSequence.is_called ||
          BigInt(afterSequence.value) > BigInt(beforeSequence.value),
      ).toBe(true);
      const current = await detail(330005);
      expect(current.review).toMatchObject({ retirada: false, revision: 0 });
      expect(current.history).toEqual([]);
      expect(
        (
          await admin.query<ContactMessage[]>(
            'SELECT * FROM public.contact_messages WHERE id_mensaje=$1',
            [rollbackReport],
          )
        )[0],
      ).toMatchObject({
        leido: false,
        respondido: false,
        fecha_lectura: null,
        id_usuario_responde: null,
      });
    } finally {
      await admin.query(
        'DROP TRIGGER qa_moderation_fail_audit ON core.review_moderation_events; DROP FUNCTION core.qa_moderation_fail_audit()',
      );
    }
  });

  it('M11 preserves linked report and append-only audit even for direct database mutations', async () => {
    const history = (await detail(330001)).history;
    expect(history.length).toBeGreaterThan(0);
    await expect(
      admin.query(
        'UPDATE core.review_moderation_events SET motivo=$1 WHERE id_evento=$2',
        ['alterado', history[0].id_evento],
      ),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      admin.query(
        'DELETE FROM core.review_moderation_events WHERE id_evento=$1',
        [history[0].id_evento],
      ),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      admin.query('TRUNCATE core.review_moderation_events'),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      admin.query('DELETE FROM public.contact_messages WHERE id_mensaje=$1', [
        reportA,
      ]),
    ).rejects.toMatchObject({ code: '23503' });
    await http()
      .delete('/company/contact/' + reportA)
      .auth(token(3), { type: 'bearer' })
      .expect(409);
    expect((await detail(330001)).history).toEqual(history);
  });

  it('M12 contact updates derive responder from session and reject actor/content spoofing', async () => {
    await http()
      .patch('/company/contact/' + reportB)
      .auth(token(3), { type: 'bearer' })
      .send({ respondido: true, id_usuario_responde: 310005 })
      .expect(400);
    await http()
      .patch('/company/contact/' + reportB)
      .auth(token(3), { type: 'bearer' })
      .send({ mensaje: 'alterado', email: 'other@qa.invalid' })
      .expect(400);
    const result = await http()
      .patch('/company/contact/' + reportB)
      .auth(token(3), { type: 'bearer' })
      .send({ respondido: true })
      .expect(200);
    expect(responseBody<ContactMessage>(result).id_usuario_responde).toBe(
      310003,
    );
    await adminGet('/company/contact/' + reportB).expect(200);
  });

  it('M13 down refuses to erase existing decisions or retired data and rolls back its ledger', async () => {
    const before = await detail(330001);
    const ledger = await admin.query<Record<string, unknown>[]>(
      'SELECT * FROM public.moderation_qa_migrations ORDER BY id',
    );
    await expect(
      admin.undoLastMigration({ transaction: 'all' }),
    ).rejects.toBeDefined();
    expect(
      await admin.query<Record<string, unknown>[]>(
        'SELECT * FROM public.moderation_qa_migrations ORDER BY id',
      ),
    ).toEqual(ledger);
    expect(await detail(330001)).toEqual(before);
    expect(
      await admin.query<Array<{ present: string | null }>>(
        "SELECT to_regclass('core.review_moderation_events')::text AS present",
      ),
    ).toEqual([{ present: 'core.review_moderation_events' }]);
  });
});
