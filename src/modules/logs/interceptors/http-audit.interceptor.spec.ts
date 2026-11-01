import { Test } from '@nestjs/testing';
import { ExecutionContextHost } from '@nestjs/core/helpers/execution-context-host';
import { lastValueFrom, of, throwError } from 'rxjs';
import { CloudflareLogService } from '../services/cloudflare-log.service';
import { HttpAuditInterceptor } from './http-audit.interceptor';

describe('HttpAuditInterceptor error boundaries', () => {
  const registerHttpEvent = jest.fn<Promise<void>, unknown[]>();
  let interceptor: HttpAuditInterceptor;

  beforeEach(async () => {
    registerHttpEvent.mockReset().mockResolvedValue(undefined);
    const module = await Test.createTestingModule({
      providers: [
        HttpAuditInterceptor,
        { provide: CloudflareLogService, useValue: { registerHttpEvent } },
      ],
    }).compile();
    interceptor = module.get(HttpAuditInterceptor);
  });

  it.each([
    { error: { status: 403 }, responseStatus: 200, expectedStatus: 403 },
    { error: 'primitive failure', responseStatus: 502, expectedStatus: 502 },
    {
      error: { status: 'invalid status' },
      responseStatus: 503,
      expectedStatus: 503,
    },
    { error: null, responseStatus: 500, expectedStatus: 500 },
  ])(
    'records a numeric status and rethrows the original error ($expectedStatus)',
    async ({ error, responseStatus, expectedStatus }) => {
      const request = { originalUrl: '/users/profile' };
      const context = new ExecutionContextHost([
        request,
        { statusCode: responseStatus },
      ]);
      const result = interceptor.intercept(context, {
        handle: () => throwError(() => error),
      });

      await expect(lastValueFrom(result)).rejects.toBe(error);
      expect(registerHttpEvent).toHaveBeenCalledTimes(1);
      const [loggedRequest, loggedStatus, duration, loggedError] =
        registerHttpEvent.mock.calls[0];
      expect(loggedRequest).toBe(request);
      expect(loggedStatus).toBe(expectedStatus);
      expect(typeof duration).toBe('number');
      expect(loggedError).toBe(error);
    },
  );

  it('keeps successful HTTP results and their response status', async () => {
    const request = { originalUrl: '/users/profile' };
    const context = new ExecutionContextHost([request, { statusCode: 201 }]);
    const result = { saved: true };

    await expect(
      lastValueFrom(
        interceptor.intercept(context, { handle: () => of(result) }),
      ),
    ).resolves.toBe(result);
    expect(registerHttpEvent.mock.calls[0][1]).toBe(201);
  });

  it('passes through non-HTTP contexts without HTTP auditing', async () => {
    const context = new ExecutionContextHost([]);
    context.setType('rpc');

    await expect(
      lastValueFrom(interceptor.intercept(context, { handle: () => of('ok') })),
    ).resolves.toBe('ok');
    expect(registerHttpEvent).not.toHaveBeenCalled();
  });
});
