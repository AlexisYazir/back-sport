import { Injectable, Logger, type NestMiddleware } from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import { createRequire } from 'node:module';

const optionalRequire = createRequire(__filename);
const patterns = [
  { regex: /(--|\|\||&&)/, rule: 'SQL_INJECTION' },
  { regex: /<script|javascript:|onerror=|onload=/, rule: 'XSS' },
  { regex: /\.\.\/|\.\.\\/, rule: 'PATH_TRAVERSAL' },
  { regex: /\$\{/, rule: 'COMMAND_INJECTION' },
  {
    regex:
      /\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|UNION\s+SELECT)\b/i,
    rule: 'SQL_KEYWORD',
  },
  { regex: /'\s*OR\s*'1'\s*=\s*'1/i, rule: 'AUTH_BYPASS' },
  { regex: /\badmin'\s*--/i, rule: 'SQL_COMMENT_INJECTION' },
  { regex: /sleep\([0-9]+\)/i, rule: 'TIME_BASED_SQLI' },
] as const;
type Rule = (typeof patterns)[number]['rule'];
type AuditMiddleware = (
  request: { originalUrl: string },
  response: Response,
  next: () => void,
) => void;
type AuditFactory = (options: {
  onFinding: (finding: unknown) => void;
}) => AuditMiddleware;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Values are inspected in memory; neither values nor property names enter logs.
function* inputStrings(request: Request) {
  const stack: { value: unknown; top: boolean; relaxed: boolean }[] = [
    { value: request.body, top: true, relaxed: false },
    { value: request.query, top: true, relaxed: false },
    { value: request.params, top: true, relaxed: false },
  ];
  const visited = new WeakSet<object>();
  while (stack.length) {
    const item = stack.pop();
    if (!item) continue;
    if (typeof item.value === 'string') {
      yield { value: item.value, relaxed: item.relaxed };
    } else if (typeof item.value === 'object' && item.value !== null) {
      if (visited.has(item.value)) continue;
      visited.add(item.value);
      for (const [key, value] of Object.entries(item.value)) {
        stack.push({
          value,
          top: false,
          relaxed: item.top && ['deviceName', 'userAgent'].includes(key),
        });
      }
    }
  }
}

@Injectable()
export class IastMiddleware implements NestMiddleware {
  private readonly logger = new Logger('IAST');
  private readonly auditMiddleware?: AuditMiddleware;

  constructor() {
    try {
      const metadata: unknown = optionalRequire(
        'express-sec-audit/package.json',
      );
      // 0.1.4's runtime contract is CSP/onFinding, not verbose/onVulnerability.
      // It retains originalUrl in a findings buffer, so it receives no raw URL.
      if (!record(metadata) || metadata.version !== '0.1.4') {
        this.logger.warn('SECURITY_AUDIT unsupported_optional_version');
        return;
      }
      const library: unknown = optionalRequire('express-sec-audit');
      if (
        !record(library) ||
        typeof library.securityAuditMiddleware !== 'function'
      ) {
        this.logger.warn('SECURITY_AUDIT unsupported_optional_contract');
        return;
      }
      const factory = library.securityAuditMiddleware as AuditFactory;
      this.auditMiddleware = factory({
        onFinding: (finding) => this.logAuditFinding(finding),
      });
      if (typeof this.auditMiddleware !== 'function') {
        this.auditMiddleware = undefined;
        this.logger.warn('SECURITY_AUDIT unsupported_optional_contract');
      }
    } catch {
      this.logger.warn('SECURITY_AUDIT optional_unavailable');
    }
  }

  use(req: Request, res: Response, next: NextFunction): void {
    const startTime = Date.now();
    const fallbackCspAudit = () => {
      res.on('finish', () => {
        if (!res.getHeader('Content-Security-Policy')) {
          this.logAuditFinding({
            ruleId: 'runtime-missing-csp',
            severity: 'medium',
          });
        }
      });
    };
    if (this.auditMiddleware) {
      try {
        this.auditMiddleware({ originalUrl: '[omitted]' }, res, () => {});
      } catch {
        this.logger.warn('SECURITY_AUDIT optional_failed');
        fallbackCspAudit();
      }
    } else {
      // Keep the known optional detector's CSP check when absent/unsupported.
      fallbackCspAudit();
    }

    const threats = new Set<Rule>();
    for (const { value, relaxed } of inputStrings(req)) {
      for (const pattern of patterns) {
        if (relaxed && pattern.rule === 'SQL_INJECTION') continue;
        if (pattern.regex.test(value)) threats.add(pattern.rule);
      }
    }
    if (threats.size) {
      this.logger.warn(`SECURITY_INPUT rules=${[...threats].sort().join(',')}`);
    }

    const originalSend = res.send.bind(res) as (body: unknown) => Response;
    res.send = (body: unknown) => {
      if (typeof body === 'string') {
        for (const { value } of inputStrings(req)) {
          if (
            ['<script', 'javascript:', 'onerror=', 'onload='].some((p) =>
              value.includes(p),
            ) &&
            body.includes(value)
          ) {
            this.logger.error('SECURITY_RESPONSE reflected_xss');
            break;
          }
        }
      }
      return originalSend(body);
    };
    res.on('finish', () => {
      if (Date.now() - startTime > 3000) {
        this.logger.warn('SECURITY_RESPONSE slow_response');
      }
    });
    next();
  }

  private logAuditFinding(finding: unknown): void {
    const rule =
      record(finding) && finding.ruleId === 'runtime-missing-csp'
        ? 'MISSING_CSP'
        : 'UNCLASSIFIED';
    const severity = record(finding) ? finding.severity : undefined;
    const level =
      typeof severity === 'string' &&
      ['low', 'medium', 'high', 'critical'].includes(severity.toLowerCase())
        ? severity.toLowerCase()
        : 'unknown';
    this.logger.warn(`SECURITY_AUDIT rule=${rule} severity=${level}`);
  }
}
