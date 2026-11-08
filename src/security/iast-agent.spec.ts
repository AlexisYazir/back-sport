import { Logger } from '@nestjs/common';
import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';
import type { Request, Response } from 'express';
import { IastMiddleware } from '../../iast-agent';

type FindingCallback = (finding: unknown) => void;
type Factory = (options: {
  onFinding: FindingCallback;
}) => (
  request: { originalUrl: string },
  response: Response,
  next: () => void,
) => void;
const nativeRequire = createRequire(__filename);
const library = nativeRequire('express-sec-audit') as {
  securityAuditMiddleware: Factory;
};
const metadata = nativeRequire('express-sec-audit/package.json') as {
  version: string;
};
const runtime = nativeRequire('express-sec-audit/src/runtime/middleware') as {
  getRuntimeFindings(): unknown[];
};
const originalFactory = library.securityAuditMiddleware;
const originalVersion = metadata.version;

function fixture(
  body: unknown = {},
  query: unknown = {},
  params: unknown = {},
) {
  const req = {
    body,
    query,
    params,
    method: 'POST',
    originalUrl: '/CANARY_PATH_SECRET?token=CANARY_QUERY_SECRET',
    headers: { authorization: 'Bearer CANARY_HEADER_SECRET' },
  } as unknown as Request;
  const emitter = new EventEmitter();
  const send = jest
    .fn<unknown, [unknown]>()
    .mockImplementation((value) => value);
  const res = Object.assign(emitter, {
    send,
    getHeader: jest.fn<unknown, [string]>().mockReturnValue(undefined),
  }) as unknown as Response;
  return { req, res, send, emitter, next: jest.fn() };
}

describe('IAST log privacy without reducing detection', () => {
  let warn: jest.SpyInstance;
  let error: jest.SpyInstance;
  let consoleLog: jest.SpyInstance;
  let consoleWarn: jest.SpyInstance;
  let consoleError: jest.SpyInstance;
  beforeEach(() => {
    warn = jest
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation(() => undefined);
    error = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    consoleLog = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    consoleWarn = jest
      .spyOn(console, 'warn')
      .mockImplementation(() => undefined);
    consoleError = jest
      .spyOn(console, 'error')
      .mockImplementation(() => undefined);
  });
  afterEach(() => {
    library.securityAuditMiddleware = originalFactory;
    metadata.version = originalVersion;
    jest.restoreAllMocks();
  });
  function logs(): string {
    return JSON.stringify([
      warn.mock.calls,
      error.mock.calls,
      consoleLog.mock.calls,
      consoleWarn.mock.calls,
      consoleError.mock.calls,
    ]);
  }

  it.each([
    'passw',
    'psw',
    'password',
    'contrasenaActual',
    'confirmPassword',
    'token',
    'refreshToken',
    'accessToken',
    'idToken',
    'authorization',
    'cookie',
  ])(
    'detects an attack in %s without logging auth values or request metadata',
    (key) => {
      const value = 'CANARY_AUTH_SECRET--Aa123!';
      const f = fixture({ [key]: value });
      const before = JSON.stringify(f.req);
      new IastMiddleware().use(f.req, f.res, f.next);
      expect(warn).toHaveBeenCalledWith('SECURITY_INPUT rules=SQL_INJECTION');
      expect(f.next).toHaveBeenCalledTimes(1);
      expect(JSON.stringify(f.req)).toBe(before);
      expect(logs()).not.toContain('CANARY_');
    },
  );

  it('inspects nested arrays, query and params without logging dynamic field names', () => {
    const f = fixture(
      { CANARY_FIELD_SECRET: { nested: ['CANARY_NESTED_SECRET<script>'] } },
      { token: 'CANARY_QUERY_SECRET../' },
      { id: 'CANARY_PARAM_SECRET${command}' },
    );
    new IastMiddleware().use(f.req, f.res, f.next);
    expect(warn).toHaveBeenCalledWith(
      'SECURITY_INPUT rules=COMMAND_INJECTION,PATH_TRAVERSAL,XSS',
    );
    expect(logs()).not.toContain('CANARY_');
  });

  it('keeps reflection and slow-response alerts while returning the same body', () => {
    const reflected = '<script>CANARY_RESPONSE_SECRET</script>';
    const f = fixture({ password: { nested: reflected } });
    const middleware = new IastMiddleware();
    jest.spyOn(Date, 'now').mockReturnValueOnce(1000).mockReturnValue(5001);
    middleware.use(f.req, f.res, f.next);
    expect(f.res.send(reflected)).toBe(reflected);
    expect(f.send).toHaveBeenCalledWith(reflected);
    f.emitter.emit('finish');
    expect(error).toHaveBeenCalledWith('SECURITY_RESPONSE reflected_xss');
    expect(warn).toHaveBeenCalledWith('SECURITY_RESPONSE slow_response');
    expect(logs()).not.toContain('CANARY_');
  });

  it('executes installed 0.1.4 CSP detection with a constant URL in its buffer', () => {
    const before = runtime.getRuntimeFindings().length;
    const f = fixture();
    new IastMiddleware().use(f.req, f.res, f.next);
    f.emitter.emit('finish');
    const findings = runtime.getRuntimeFindings().slice(before);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'runtime-missing-csp',
      route: '[omitted]',
    });
    expect(warn).toHaveBeenCalledWith(
      'SECURITY_AUDIT rule=MISSING_CSP severity=medium',
    );
    expect(logs()).not.toContain('CANARY_');
  });

  it('allows only finite callback metadata and gives the optional auditor no raw request', () => {
    const audit = jest.fn((request, _response, next: () => void) => next());
    library.securityAuditMiddleware = jest.fn((options) => {
      expect(Object.keys(options)).toEqual(['onFinding']);
      options.onFinding({
        ruleId: 'CANARY_RULE_SECRET',
        severity: 'CANARY_SEVERITY_SECRET',
        payload: 'CANARY_PAYLOAD_SECRET',
        url: 'CANARY_URL_SECRET',
        parameter: 'CANARY_FIELD_SECRET',
      });
      return audit;
    });
    const f = fixture({ psw: 'CANARY_BODY_SECRET' });
    new IastMiddleware().use(f.req, f.res, f.next);
    expect(audit.mock.calls[0][0]).toEqual({ originalUrl: '[omitted]' });
    expect(warn).toHaveBeenCalledWith(
      'SECURITY_AUDIT rule=UNCLASSIFIED severity=unknown',
    );
    expect(f.next).toHaveBeenCalledTimes(1);
    expect(logs()).not.toContain('CANARY_');
  });

  it('reports an unsupported version and preserves custom and fallback CSP checks', () => {
    metadata.version = '99.0.0';
    const factory = jest.fn(originalFactory);
    library.securityAuditMiddleware = factory;
    const f = fixture({ psw: 'CANARY_SECRET--' });
    new IastMiddleware().use(f.req, f.res, f.next);
    f.emitter.emit('finish');
    expect(factory).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledWith(
      'SECURITY_AUDIT unsupported_optional_version',
    );
    expect(warn).toHaveBeenCalledWith('SECURITY_INPUT rules=SQL_INJECTION');
    expect(warn).toHaveBeenCalledWith(
      'SECURITY_AUDIT rule=MISSING_CSP severity=medium',
    );
    expect(logs()).not.toContain('CANARY_');
  });

  it('uses fallback CSP after an optional failure without logging the thrown value', () => {
    library.securityAuditMiddleware = () => () => {
      throw new Error('CANARY_EXCEPTION_SECRET');
    };
    const f = fixture();
    new IastMiddleware().use(f.req, f.res, f.next);
    f.emitter.emit('finish');
    expect(warn).toHaveBeenCalledWith('SECURITY_AUDIT optional_failed');
    expect(warn).toHaveBeenCalledWith(
      'SECURITY_AUDIT rule=MISSING_CSP severity=medium',
    );
    expect(f.next).toHaveBeenCalledTimes(1);
    expect(logs()).not.toContain('CANARY_');
  });

  it('does not flag benign inputs, preserves relaxed fields and handles cycles', () => {
    const body: Record<string, unknown> = {
      name: 'Ana',
      deviceName: 'Android--17',
      userAgent: 'client||1',
    };
    body.self = body;
    const f = fixture(body, {}, {});
    (f.res.getHeader as jest.Mock).mockReturnValue("default-src 'self'");
    new IastMiddleware().use(f.req, f.res, f.next);
    const response = { ok: true };
    expect(f.res.send(response)).toBe(response);
    f.emitter.emit('finish');
    expect(f.next).toHaveBeenCalledTimes(1);
    expect(warn).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  });
});
