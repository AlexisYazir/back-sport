import type { Server } from 'node:http';
import { BadRequestException, type INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import { getDataSourceToken } from '@nestjs/typeorm';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import * as jwt from 'jsonwebtoken';
import request from 'supertest';
import { configureHttpApplication } from '../../config/http-application';
import { JwtStrategy } from '../../services/auth/jwt.strategy';
import { RolesGuard } from '../../services/auth/roles.guard';
import { ActiveAdminGuard } from '../../services/auth/active-admin.guard';
import { UsersService } from '../users/users.service';
import { DbBackupController } from '../backups/controllers/db-backup.controller';
import { DbBackupService } from '../backups/services/db-backup.service';
import { AccountDeletionAccessService } from './account-deletion-access.service';
import { AccountDeletionController } from './account-deletion.controller';
import { AccountDeletionService } from './account-deletion.service';
import {
  AccountDeletionMutationGuard,
  DeletionNoStoreInterceptor,
} from './account-deletion.guards';
import type { DeletionPrincipal, DeletionResult } from './deletion.types';

const secret = 'synthetic-http-jwt-key-only-for-isolated-tests';
const id = 'd539155c-3bb7-44b6-8d12-d53b9d4ff642';
const base = '/users/account-deletion';
const operation = `${base}/requests/${id}`;
const confirmationToken = 'C'.repeat(43);
const receiptToken = 'R'.repeat(43);
const webOrigin = 'https://sport-center-sitie.netlify.app';
const customerA = { id_usuario: 41, rol: 1, sessionId: 'synthetic-session-A' };
const customerB = { id_usuario: 42, rol: 1, sessionId: 'synthetic-session-B' };
const employee = {
  id_usuario: 43,
  rol: 2,
  sessionId: 'synthetic-session-employee',
};
const administrator = {
  id_usuario: 51,
  rol: 3,
  sessionId: 'synthetic-session-admin',
};
const inactiveAdmin = {
  id_usuario: 52,
  rol: 3,
  sessionId: 'synthetic-session-inactive-admin',
};
const activeSessions = new Set(
  [customerA, customerB, employee, administrator, inactiveAdmin].map(
    (actor) => actor.sessionId,
  ),
);

function signed(actor: DeletionPrincipal) {
  return jwt.sign(
    { ...actor, email: 'synthetic@example.test', nombre: 'Cliente de prueba' },
    secret,
    { expiresIn: '5m' },
  );
}

const customerAToken = signed(customerA);
const customerBToken = signed(customerB);
const employeeToken = signed(employee);
const adminToken = signed(administrator);
const inactiveAdminToken = signed(inactiveAdmin);

function deletionResult(
  status: DeletionResult['status'] = 'completed',
): DeletionResult {
  return {
    requestId: id,
    status,
    reason: null,
    retainedCategories: [],
    notification: 'not_required',
  };
}

function mockService() {
  return {
    execute: jest.fn<Promise<DeletionResult>, []>(),
    request: jest.fn<Promise<unknown>, [DeletionPrincipal]>(),
    verify: jest.fn<Promise<unknown>, [DeletionPrincipal, string, string]>(),
    confirm: jest.fn<
      Promise<DeletionResult>,
      [DeletionPrincipal, string, string, boolean]
    >(),
    result: jest.fn<Promise<DeletionResult>, [string, string]>(),
    listPending: jest.fn<Promise<DeletionResult[]>, []>(),
    process: jest.fn<
      Promise<DeletionResult>,
      [string, { basis: string; days: number }?]
    >(),
  };
}

describe('Account deletion HTTP contract with real JWT, validation and origin guards', () => {
  let app: INestApplication<Server>;
  const service = mockService();
  const backups = { listBackups: jest.fn<Promise<unknown[]>, []>() };
  const reader = {
    query: jest.fn<Promise<{ id_usuario: number }[]>, [string, number[]]>(),
  };
  const access = { assertAllowed: jest.fn<Promise<void>, [number]>() };
  const users = { isSessionActive: jest.fn<Promise<boolean>, [string]>() };

  beforeAll(async () => {
    const module = await Test.createTestingModule({
      imports: [PassportModule.register({ defaultStrategy: 'jwt' })],
      controllers: [AccountDeletionController, DbBackupController],
      providers: [
        JwtStrategy,
        RolesGuard,
        ActiveAdminGuard,
        AccountDeletionMutationGuard,
        DeletionNoStoreInterceptor,
        { provide: AccountDeletionService, useValue: service },
        { provide: DbBackupService, useValue: backups },
        { provide: UsersService, useValue: users },
        { provide: AccountDeletionAccessService, useValue: access },
        { provide: getDataSourceToken('readerConnection'), useValue: reader },
        {
          provide: ConfigService,
          useValue: {
            getOrThrow: () => secret,
            get: (key: string) =>
              key === 'FRONTEND_URL' ? webOrigin : undefined,
          },
        },
      ],
    }).compile();
    app = module.createNestApplication<INestApplication<Server>>();
    app.useLogger(false);
    configureHttpApplication(app);
    await app.init();
  });

  beforeEach(() => {
    for (const mock of Object.values(service)) mock.mockReset();
    backups.listBackups.mockReset().mockResolvedValue([]);
    reader.query
      .mockReset()
      .mockImplementation((_sql, parameters) =>
        Promise.resolve(
          parameters[0] === administrator.id_usuario
            ? [{ id_usuario: administrator.id_usuario }]
            : [],
        ),
      );
    access.assertAllowed.mockReset().mockResolvedValue(undefined);
    users.isSessionActive
      .mockReset()
      .mockImplementation((session) =>
        Promise.resolve(activeSessions.has(session)),
      );
    service.execute.mockResolvedValue(deletionResult());
    service.request.mockResolvedValue({
      requestId: id,
      status: 'received',
      receiptToken,
      expiresAt: '2030-01-01T00:10:00.000Z',
    });
    service.verify.mockResolvedValue({
      status: 'identity_verified',
      confirmationToken,
    });
    service.confirm.mockImplementation((_actor, _id, _token, confirmed) => {
      if (confirmed !== true)
        throw new BadRequestException(
          'Debes confirmar expresamente la eliminación',
        );
      return service.execute();
    });
    service.result.mockResolvedValue(deletionResult());
    service.listPending.mockResolvedValue([
      deletionResult('requires_attention'),
    ]);
    service.process.mockResolvedValue(deletionResult());
  });

  afterAll(async () => {
    await app.close();
  });

  it('derives the initiating owner from JWT rather than client-supplied identity', async () => {
    await request(app.getHttpServer())
      .post(`${base}/requests`)
      .set('Authorization', `Bearer ${customerAToken}`)
      .send({
        id_usuario: customerB.id_usuario,
        email: 'untrusted@example.test',
      })
      .expect(201);
    expect(service.request).toHaveBeenCalledWith(
      expect.objectContaining(customerA),
    );
    expect(service.execute).not.toHaveBeenCalled();
  });

  it('prefers explicit Bearer B over incidental cookie A on mobile without Origin', async () => {
    await request(app.getHttpServer())
      .post(`${base}/requests`)
      .set('Authorization', `Bearer ${customerBToken}`)
      .set('Cookie', `sc_access_token=${customerAToken}`)
      .send({})
      .expect(201);
    expect(service.request).toHaveBeenCalledWith(
      expect.objectContaining(customerB),
    );
    expect(access.assertAllowed).toHaveBeenCalledWith(customerB.id_usuario);
    expect(access.assertAllowed).not.toHaveBeenCalledWith(customerA.id_usuario);
  });

  it.each([
    'Bearer invalid-synthetic-token',
    'Bearer',
    'Basic invalid-synthetic-token',
  ])(
    'does not fall back to cookie authentication for explicit invalid header %s',
    async (authorization) => {
      await request(app.getHttpServer())
        .post(`${base}/requests`)
        .set('Authorization', authorization)
        .set('Cookie', `sc_access_token=${customerAToken}`)
        .set('Origin', webOrigin)
        .send({})
        .expect(401);
      expect(service.request).not.toHaveBeenCalled();
    },
  );

  it('rejects missing authentication before creating a request', async () => {
    await request(app.getHttpServer())
      .post(`${base}/requests`)
      .send({})
      .expect(401);
    expect(service.request).not.toHaveBeenCalled();
  });

  it('rejects cookie-only mutation without Origin', async () => {
    await request(app.getHttpServer())
      .post(`${base}/requests`)
      .set('Cookie', `sc_access_token=${customerAToken}`)
      .send({})
      .expect(403);
    expect(service.request).not.toHaveBeenCalled();
  });

  it('accepts cookie authentication from the allowed web Origin', async () => {
    await request(app.getHttpServer())
      .post(`${base}/requests`)
      .set('Cookie', `sc_access_token=${customerAToken}`)
      .set('Origin', webOrigin)
      .send({})
      .expect(201);
    expect(service.request).toHaveBeenCalledWith(
      expect.objectContaining(customerA),
    );
  });

  it.each(['cookie', 'bearer', 'both'] as const)(
    'rejects attacker Origin with %s authentication',
    async (kind) => {
      const req = request(app.getHttpServer())
        .post(`${base}/requests`)
        .set('Origin', 'https://attacker.example.test');
      if (kind !== 'bearer')
        req.set('Cookie', `sc_access_token=${customerAToken}`);
      if (kind !== 'cookie')
        req.set('Authorization', `Bearer ${customerBToken}`);
      await req.send({}).expect(403);
      expect(service.request).not.toHaveBeenCalled();
    },
  );

  it('requires JSON for authenticated mutations', async () => {
    await request(app.getHttpServer())
      .post(`${base}/requests`)
      .set('Authorization', `Bearer ${customerAToken}`)
      .type('form')
      .send('confirmed=true')
      .expect(403);
    expect(service.request).not.toHaveBeenCalled();
  });

  it('passes a six-digit verification code with its leading zero intact', async () => {
    await request(app.getHttpServer())
      .post(`${operation}/verify`)
      .set('Authorization', `Bearer ${customerAToken}`)
      .send({ code: '012345' })
      .expect(201);
    expect(service.verify).toHaveBeenCalledWith(
      expect.objectContaining(customerA),
      id,
      '012345',
    );
    expect(service.execute).not.toHaveBeenCalled();
  });

  it.each(['12345', '1234567', '12a456', ' 123456', 123456, null])(
    'rejects invalid verification code %p before service invocation',
    async (code) => {
      await request(app.getHttpServer())
        .post(`${operation}/verify`)
        .set('Authorization', `Bearer ${customerAToken}`)
        .send({ code })
        .expect(400);
      expect(service.verify).not.toHaveBeenCalled();
    },
  );

  it('rejects unknown verification body fields and malformed request IDs', async () => {
    await request(app.getHttpServer())
      .post(`${operation}/verify`)
      .set('Authorization', `Bearer ${customerAToken}`)
      .send({ code: '123456', userId: 99 })
      .expect(400);
    await request(app.getHttpServer())
      .post(`${base}/requests/not-a-uuid/verify`)
      .set('Authorization', `Bearer ${customerAToken}`)
      .send({ code: '123456' })
      .expect(400);
    expect(service.verify).not.toHaveBeenCalled();
  });

  it('passes false without coercion and does not clear cookies on rejected confirmation', async () => {
    const response = await request(app.getHttpServer())
      .post(`${operation}/confirm`)
      .set('Authorization', `Bearer ${customerAToken}`)
      .send({ confirmationToken, confirmed: false })
      .expect(400);
    expect(service.confirm).toHaveBeenCalledWith(
      expect.objectContaining(customerA),
      id,
      confirmationToken,
      false,
    );
    expect(service.execute).not.toHaveBeenCalled();
    expect(response.headers['set-cookie']).toBeUndefined();
  });

  it.each(['false', 'true', 0, 1, null])(
    'rejects a non-boolean confirmation %p',
    async (confirmed) => {
      await request(app.getHttpServer())
        .post(`${operation}/confirm`)
        .set('Authorization', `Bearer ${customerAToken}`)
        .send({ confirmationToken, confirmed })
        .expect(400);
      expect(service.confirm).not.toHaveBeenCalled();
    },
  );

  it('returns the confirmed result unchanged, clears both cookie variants and disables caching', async () => {
    service.execute.mockResolvedValue(deletionResult('requires_attention'));
    const response = await request(app.getHttpServer())
      .post(`${operation}/confirm`)
      .set('Authorization', `Bearer ${customerAToken}`)
      .send({ confirmationToken, confirmed: true })
      .expect(201);
    expect(response.body as unknown).toEqual(
      deletionResult('requires_attention'),
    );
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.pragma).toBe('no-cache');
    const cookies = response.headers['set-cookie'] as unknown as string[];
    expect(
      cookies.filter((cookie) => cookie.startsWith('sc_access_token=')).length,
    ).toBe(2);
    expect(
      cookies.filter((cookie) => cookie.startsWith('sc_refresh_token=')).length,
    ).toBe(2);
    expect(service.execute).toHaveBeenCalledTimes(1);
  });

  it('accepts a result receipt only in the POST body without JWT, including an incidental cookie', async () => {
    await request(app.getHttpServer())
      .post(`${operation}/result`)
      .set('Cookie', 'sc_access_token=expired-incidental-cookie')
      .send({ receiptToken })
      .expect(201);
    expect(service.result).toHaveBeenCalledWith(id, receiptToken);
    expect(access.assertAllowed).not.toHaveBeenCalled();
    expect(service.execute).not.toHaveBeenCalled();
    await request(app.getHttpServer()).get(`${operation}/result`).expect(404);
  });

  it.each([{}, { receiptToken: 'short' }, { receiptToken, userId: 1 }])(
    'rejects an invalid receipt body %p',
    async (body) => {
      await request(app.getHttpServer())
        .post(`${operation}/result`)
        .send(body)
        .expect(400);
      expect(service.result).not.toHaveBeenCalled();
    },
  );

  it.each([
    'received',
    'in_progress',
    'requires_attention',
    'error',
    'completed',
  ] as const)(
    'preserves actual result state %s with no-store headers',
    async (status) => {
      const result = deletionResult(status);
      service.result.mockResolvedValue(result);
      const response = await request(app.getHttpServer())
        .post(`${operation}/result`)
        .send({ receiptToken })
        .expect(201);
      expect(response.body as unknown).toEqual(result);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers.pragma).toBe('no-cache');
    },
  );

  it('rejects receipt reads from an attacker Origin despite the body capability', async () => {
    await request(app.getHttpServer())
      .post(`${operation}/result`)
      .set('Origin', 'https://attacker.example.test')
      .send({ receiptToken })
      .expect(403);
    expect(service.result).not.toHaveBeenCalled();
  });

  it('restricts the administrative queue to an active administrator', async () => {
    await request(app.getHttpServer())
      .get(`${base}/admin/requests`)
      .expect(401);
    await request(app.getHttpServer())
      .get(`${base}/admin/requests`)
      .set('Authorization', `Bearer ${employeeToken}`)
      .expect(403);
    await request(app.getHttpServer())
      .get(`${base}/admin/requests`)
      .set('Authorization', `Bearer ${inactiveAdminToken}`)
      .expect(403);
    expect(service.listPending).not.toHaveBeenCalled();
    const response = await request(app.getHttpServer())
      .get(`${base}/admin/requests`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);
    expect(response.body as unknown).toEqual([
      deletionResult('requires_attention'),
    ]);
    expect(service.listPending).toHaveBeenCalledTimes(1);
    expect(reader.query).toHaveBeenCalledWith(
      expect.stringContaining('rol = 3 AND activo = 1'),
      [administrator.id_usuario],
    );
  });

  it('does not trust an administrative JWT if the current permission lookup fails', async () => {
    reader.query.mockRejectedValue(new Error('isolated-reader-failure'));
    await request(app.getHttpServer())
      .get(`${base}/admin/requests`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(503);
    expect(service.listPending).not.toHaveBeenCalled();
  });

  it('validates the administrative processing action before invoking it', async () => {
    await request(app.getHttpServer())
      .post(`${base}/admin/requests/${id}/process`)
      .set('Authorization', `Bearer ${employeeToken}`)
      .send({})
      .expect(403);
    await request(app.getHttpServer())
      .post(`${base}/admin/requests/${id}/process`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ basis: 'short', days: 0 })
      .expect(400);
    expect(service.process).not.toHaveBeenCalled();
    await request(app.getHttpServer())
      .post(`${base}/admin/requests/${id}/process`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ basis: 'Obligación legal de prueba', days: 90 })
      .expect(201);
    expect(service.process).toHaveBeenCalledWith(id, {
      basis: 'Obligación legal de prueba',
      days: 90,
    });
  });

  it('applies JWT, role and active-admin guards to the backup controller at class scope', async () => {
    const guards = Reflect.getMetadata(
      GUARDS_METADATA,
      DbBackupController,
    ) as unknown as unknown[];
    expect(guards).toContain(RolesGuard);
    expect(guards).toContain(ActiveAdminGuard);
    expect(Reflect.getMetadata('roles', DbBackupController) as unknown).toEqual(
      [3],
    );
    await request(app.getHttpServer()).get('/backup/list').expect(401);
    await request(app.getHttpServer())
      .get('/backup/list')
      .set('Authorization', `Bearer ${employeeToken}`)
      .expect(403);
    await request(app.getHttpServer())
      .get('/backup/list')
      .set('Authorization', `Bearer ${inactiveAdminToken}`)
      .expect(403);
    expect(backups.listBackups).not.toHaveBeenCalled();
    await request(app.getHttpServer())
      .get('/backup/list')
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200, []);
    expect(backups.listBackups).toHaveBeenCalledTimes(1);
  });
});
