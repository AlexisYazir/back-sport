import express from 'express';
import request from 'supertest';
import { createHttpRequestLogger } from './http-request-logger';
import { requestLogMetadata } from './request-log-metadata';

describe('HTTP logger uses server route templates', () => {
  it('logs the matched template and status without credentials in query/path/headers', async () => {
    const lines: string[] = [];
    const app = express();
    app.use(
      createHttpRequestLogger({
        stream: {
          write: (line) => {
            lines.push(line);
          },
        },
      }),
    );
    app.get('/users/:id', (req, res) => {
      expect(req.originalUrl).toContain('CANARY_QUERY_SECRET');
      res.status(202).json({ id: req.params.id });
    });
    const result = await request(app)
      .get('/users/CANARY_PATH_SECRET?token=CANARY_QUERY_SECRET')
      .set('authorization', 'Bearer CANARY_HEADER_SECRET')
      .expect(202);
    expect(result.body).toEqual({ id: 'CANARY_PATH_SECRET' });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('GET /users/:id HTTP/1.1');
    expect(lines[0]).toContain('202');
    expect(lines.join('')).not.toContain('CANARY_');
  });

  it('uses a constant for an unmatched path and constrains method metadata', async () => {
    const lines: string[] = [];
    const app = express();
    app.use(
      createHttpRequestLogger({
        stream: {
          write: (line) => {
            lines.push(line);
          },
        },
      }),
    );
    await request(app)
      .get('/CANARY_UNMATCHED_SECRET?token=CANARY_QUERY_SECRET')
      .expect(404);
    expect(lines[0]).toContain('GET [unmatched]');
    expect(lines.join('')).not.toContain('CANARY_');
    expect(requestLogMetadata({ method: 'CANARY_METHOD_SECRET' })).toEqual({
      method: 'OTHER',
      path: '[unmatched]',
    });
    expect(
      requestLogMetadata({
        method: 'get',
        route: { path: '/users?token=CANARY_SECRET' },
      }).path,
    ).toBe('[unmatched]');
  });
});
