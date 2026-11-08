import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import express from 'express';
import request from 'supertest';
import { MailService } from '../../../services/mail/mail.service';
import { R2StorageService } from '../../backups/services/r2-storage.service';
import { CloudflareLogService } from './cloudflare-log.service';
import { Logger } from '@nestjs/common';
import type { HttpAuditRequest } from '../http-audit.types';

interface AuditScenario {
  path: string;
  statusCode: number;
  error?: unknown;
  user?: object;
  session?: unknown;
}

describe('CloudflareLogService HTTP audit boundaries', () => {
  const downloadText = jest.fn<Promise<string>, [string]>();
  const uploadText = jest.fn<Promise<void>, [string, string, string?]>();
  const sendCriticalAlertEmail = jest.fn<
    Promise<void>,
    [string, string, string]
  >();
  let service: CloudflareLogService;

  beforeEach(async () => {
    downloadText.mockReset().mockResolvedValue('');
    uploadText.mockReset().mockResolvedValue(undefined);
    sendCriticalAlertEmail.mockReset().mockResolvedValue(undefined);
    const module = await Test.createTestingModule({
      providers: [
        CloudflareLogService,
        {
          provide: R2StorageService,
          useValue: { downloadText, uploadText },
        },
        { provide: MailService, useValue: { sendCriticalAlertEmail } },
        {
          provide: ConfigService,
          useValue: new ConfigService({
            LOG_ALERT_EMAIL: 'audit@example.test',
          }),
        },
      ],
    }).compile();
    service = module.get(CloudflareLogService);
  });
  afterEach(() => jest.restoreAllMocks());

  function auditApp(scenario: AuditScenario) {
    const app = express();
    app.use(express.json({ strict: false }));
    app.post(scenario.path, (req, res, next) => {
      const auditRequest = Object.assign(req, {
        user: scenario.user,
        session: scenario.session,
      });
      service
        .registerHttpEvent(
          auditRequest,
          scenario.statusCode,
          12,
          scenario.error,
        )
        .then(() => res.sendStatus(scenario.statusCode))
        .catch(next);
    });
    return app;
  }

  function savedEntry(): unknown {
    return JSON.parse(uploadText.mock.calls[0][1]);
  }

  it('preserves identity precedence and omits unrelated secrets', async () => {
    const app = auditApp({
      path: '/users/login-user',
      statusCode: 401,
      user: {
        email: 'signed-in@example.test',
        id_usuario: 42,
        id: 99,
        sessionId: '11111111-1111-4111-8111-111111111111',
        session_id: '22222222-2222-4222-8222-222222222222',
      },
      session: { id: '33333333-3333-4333-8333-333333333333' },
    });
    await request(app)
      .post('/users/login-user?email=query@example.test')
      .set('authorization', 'Bearer secret-access-token')
      .set('cookie', 'sc_access_token=secret-cookie')
      .set('x-session-id', '44444444-4444-4444-8444-444444444444')
      .send({
        email: 'body@example.test',
        correo: 'legacy@example.test',
        password: 'secret-password',
      })
      .expect(401);

    expect(savedEntry()).toMatchObject({
      level: 'warn',
      module: 'users',
      event: 'inicio_de_sesion_fallido',
      data: {
        method: 'POST',
        statusCode: 401,
        durationMs: 12,
        email: 'signed-in@example.test',
        userId: 42,
        sessionId: '11111111-1111-4111-8111-111111111111',
      },
    });
    const serialized = uploadText.mock.calls[0][1];
    for (const secret of [
      'secret-access-token',
      'secret-cookie',
      'secret-password',
    ]) {
      expect(serialized).not.toContain(secret);
    }
    expect(sendCriticalAlertEmail).not.toHaveBeenCalled();
  });

  it('handles primitive bodies and errors using the same audit defaults', async () => {
    const app = auditApp({
      path: '/users/update-user',
      statusCode: 500,
      error: 'unexpected primitive failure',
      session: 'invalid session context',
    });
    await request(app)
      .post('/users/update-user?email=query@example.test')
      .set('x-session-id', '44444444-4444-4444-8444-444444444444')
      .set('content-type', 'application/json')
      .send('"primitive body"')
      .expect(500);

    expect(savedEntry()).toMatchObject({
      level: 'error',
      event: 'consulta_sql_con_errores',
      data: {
        email: 'query@example.test',
        userId: null,
        sessionId: '44444444-4444-4444-8444-444444444444',
        error: { name: 'Error', message: 'Request failed' },
      },
    });
  });

  it('retains query error classification without persisting arbitrary error details', async () => {
    const app = auditApp({
      path: '/orders/create',
      statusCode: 400,
      error: { name: 'QueryFailedError', message: 'CANARY_QUERY_ERROR_SECRET' },
    });
    await request(app).post('/orders/create').send({}).expect(400);

    expect(savedEntry()).toMatchObject({
      level: 'error',
      event: 'consulta_sql_con_errores',
      data: {
        error: { name: 'QueryFailedError', message: 'Request failed' },
      },
    });
  });

  it('keeps critical role changes and their email alert content', async () => {
    const app = auditApp({
      path: '/users/update-user',
      statusCode: 200,
    });
    await request(app)
      .post('/users/update-user')
      .send({ id_rol: 3, correo: 'operator@example.test' })
      .expect(200);

    expect(savedEntry()).toMatchObject({
      level: 'critical',
      event: 'modificacion_de_roles_de_usuario',
      data: { email: 'operator@example.test' },
    });
    expect(sendCriticalAlertEmail).toHaveBeenCalledTimes(1);
    const [destination, subject, html] = sendCriticalAlertEmail.mock.calls[0];
    expect(destination).toBe('audit@example.test');
    expect(subject).toContain('Modificacion De Roles De Usuario');
    expect(html).toContain('<li><b>Método:</b> POST</li>');
    expect(html).toContain('<li><b>Ruta:</b> /users/update-user</li>');
    expect(html).toContain('<li><b>Usuario:</b> operator@example.test</li>');
  });

  it('skips the logs module and ordinary informational requests', async () => {
    const logs = auditApp({ path: '/logs', statusCode: 500 });
    await request(logs).post('/logs').send({}).expect(500);
    const ordinary = auditApp({ path: '/users/profile', statusCode: 200 });
    await request(ordinary).post('/users/profile').send({}).expect(200);

    expect(uploadText).not.toHaveBeenCalled();
    expect(sendCriticalAlertEmail).not.toHaveBeenCalled();
  });

  it('persists only the route template and finite error metadata', async () => {
    const app = auditApp({
      path: '/users/:id',
      statusCode: 500,
      error: Object.assign(new Error('CANARY_ERROR_MESSAGE'), {
        name: 'CANARY_ERROR_NAME',
      }),
    });
    await request(app)
      .post('/users/CANARY_PATH_SECRET?token=CANARY_QUERY_SECRET')
      .send({ password: 'CANARY_PASSWORD_SECRET' })
      .expect(500);
    expect(savedEntry()).toMatchObject({
      module: 'users',
      event: 'consulta_sql_con_errores',
      data: {
        path: '/users/:id',
        error: { name: 'Error', message: 'Request failed' },
      },
    });
    expect(uploadText.mock.calls[0][1]).not.toContain('CANARY_');
  });

  it('rejects objects and arrays in identity/header metadata and hides unmatched path segments', async () => {
    const secret = { refreshToken: 'CANARY_NESTED_SECRET' };
    const input = {
      method: 'POST',
      originalUrl:
        '/CANARY_MODULE_SECRET/users/login-user?token=CANARY_QUERY_SECRET',
      body: { email: secret, correo: [secret] },
      query: { email: secret },
      user: {
        email: secret,
        id_usuario: secret,
        id: [secret],
        sessionId: secret,
        session_id: [secret],
      },
      session: { id: secret },
      headers: { 'x-session-id': [secret], 'user-agent': secret },
      ip: secret,
      socket: { remoteAddress: secret },
    } as unknown as HttpAuditRequest;
    const before = JSON.stringify(input);
    await service.registerHttpEvent(input, 401, 12);
    expect(savedEntry()).toMatchObject({
      module: 'system',
      event: 'inicio_de_sesion_fallido',
      data: {
        path: '[unmatched]',
        email: null,
        userId: null,
        sessionId: null,
        ip: null,
        userAgent: null,
      },
    });
    expect(uploadText.mock.calls[0][1]).not.toContain('CANARY_');
    expect(JSON.stringify(input)).toBe(before);
  });

  it('retains precedence of valid scalar identities, skipping invalid candidates', async () => {
    const input = {
      method: 'POST',
      originalUrl: '/users/update-user',
      route: { path: '/users/update-user' },
      body: { email: 'body@example.test' },
      query: { email: 'query@example.test' },
      user: {
        email: { token: 'CANARY_EMAIL_SECRET' },
        id_usuario: [],
        id: 42,
        sessionId: {},
        session_id: '22222222-2222-4222-8222-222222222222',
      },
      session: { id: '33333333-3333-4333-8333-333333333333' },
      headers: {
        'x-session-id': '44444444-4444-4444-8444-444444444444',
        'user-agent': 'okhttp/4.12',
      },
      ip: {},
      socket: { remoteAddress: '127.0.0.1' },
    } as unknown as HttpAuditRequest;
    await service.registerHttpEvent(input, 403, 12);
    expect(savedEntry()).toMatchObject({
      data: {
        email: 'body@example.test',
        userId: 42,
        sessionId: '22222222-2222-4222-8222-222222222222',
        ip: '127.0.0.1',
        userAgent: 'okhttp/4.12',
      },
    });
    expect(uploadText.mock.calls[0][1]).not.toContain('CANARY_');
  });

  it('escapes dynamic HTML in critical alerts while retaining readable audit text', async () => {
    const markup =
      '<img src="https://example.invalid/CANARY_IMAGE" onerror="CANARY_JS"> & \'text\'';
    const app = auditApp({ path: '/users/update-user', statusCode: 200 });
    await request(app)
      .post('/users/update-user')
      .set('user-agent', markup)
      .send({ id_rol: 3, correo: 'operator@example.test' })
      .expect(200);
    const html = sendCriticalAlertEmail.mock.calls[0][2];
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
    expect(html).toContain('&quot;');
    expect(html).toContain('&amp;');
    expect(html).toContain('&#39;');
    expect(savedEntry()).toMatchObject({ data: { userAgent: markup } });
  });

  it('does not log a raw critical-alert delivery failure', async () => {
    const log = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    sendCriticalAlertEmail.mockRejectedValueOnce(
      new Error('CANARY_MAIL_ERROR_SECRET'),
    );
    const app = auditApp({ path: '/users/update-user', statusCode: 200 });
    await request(app)
      .post('/users/update-user')
      .send({ id_rol: 3 })
      .expect(200);
    expect(log).toHaveBeenCalledWith('Critical audit alert delivery failed');
    expect(JSON.stringify(log.mock.calls)).not.toContain('CANARY_');
  });
});
