import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import express from 'express';
import request from 'supertest';
import { MailService } from '../../../services/mail/mail.service';
import { R2StorageService } from '../../backups/services/r2-storage.service';
import { CloudflareLogService } from './cloudflare-log.service';

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
        sessionId: 'user-session',
        session_id: 'legacy-session',
      },
      session: { id: 'request-session' },
    });
    await request(app)
      .post('/users/login-user?email=query@example.test')
      .set('authorization', 'Bearer secret-access-token')
      .set('cookie', 'sc_access_token=secret-cookie')
      .set('x-session-id', 'header-session')
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
        sessionId: 'user-session',
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
      .set('x-session-id', 'header-session')
      .set('content-type', 'application/json')
      .send('"primitive body"')
      .expect(500);

    expect(savedEntry()).toMatchObject({
      level: 'error',
      event: 'consulta_sql_con_errores',
      data: {
        email: 'query@example.test',
        userId: null,
        sessionId: 'header-session',
        error: { name: 'Error', message: 'Unexpected error' },
      },
    });
  });

  it('retains query error classification and details from non-Error objects', async () => {
    const app = auditApp({
      path: '/orders/create',
      statusCode: 400,
      error: { name: 'QueryFailedError', message: 'constraint failed' },
    });
    await request(app).post('/orders/create').send({}).expect(400);

    expect(savedEntry()).toMatchObject({
      level: 'error',
      event: 'consulta_sql_con_errores',
      data: {
        error: { name: 'QueryFailedError', message: 'constraint failed' },
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
});
