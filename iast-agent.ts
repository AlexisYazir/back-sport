/* eslint-disable */
import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

// middleware de express-sec-audit
let securityAuditMiddleware: any;
try {
  const expressSecAudit = require('express-sec-audit');
  securityAuditMiddleware = expressSecAudit.securityAuditMiddleware;
  console.log('express-sec-audit middleware cargado correctamente');
} catch (error) {
  console.warn(
    'express-sec-audit no instalado, usando solo detección personalizada',
  );
}

@Injectable()
export class IastMiddleware implements NestMiddleware {
  private readonly logger = new Logger('IAST');
  private readonly auditMiddleware: any;
  private readonly sensitiveFields = new Set([
    'passw',
    'password',
    'token',
    'refreshToken',
    'accessToken',
    'authorization',
    'idToken',
  ]);
  private readonly relaxedFields = new Set(['deviceName', 'userAgent']);

  constructor() {
    if (securityAuditMiddleware) {
      // Configurar el middleware de express-sec-audit.
      this.auditMiddleware = securityAuditMiddleware({
        realtime: true,
        logLevel: 'verbose',
        detectSqlInjection: true,
        detectXss: true,
        detectCommandInjection: true,
        detectPathTraversal: true,
        onVulnerability: (vuln: any) => {
          this.logger.warn(
            `[express-sec-audit] VULNERABILIDAD: ${vuln.type || 'Desconocida'}`,
          );
          this.logger.warn(`${vuln.method || '?'} ${vuln.url || '?'}`);
          this.logger.warn(`Severidad: ${vuln.severity || 'MEDIUM'}`);
          if (vuln.payload) this.logger.warn(`Payload: ${vuln.payload}`);
          if (vuln.parameter)
            this.logger.warn(`Campo: ${vuln.parameter}`);
        },
      });
    }
  }

  use(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();

    // 1. Ejecutar middleware de express-sec-audit si está disponible
    if (this.auditMiddleware) {
      this.auditMiddleware(req, res, () => {});
    }

    // 2. Análisis personalizado de amenazas
    const threats = this.detectThreats(req);

    if (threats.length > 0) {
      this.logger.warn('ATAQUE DETECTADO');
      this.logger.warn(`Endpoint: ${req.method} ${req.originalUrl}`);
      this.logger.warn(`Patrones: ${threats.join(', ')}`);
      if (Object.keys(req.body).length > 0) {
        this.logger.warn(`Body: ${JSON.stringify(this.sanitizeForLog(req.body))}`);
      }
      if (Object.keys(req.query).length > 0) {
        this.logger.warn(`Query: ${JSON.stringify(this.sanitizeForLog(req.query))}`);
      }
    }

    // 3. Interceptar respuesta para detectar XSS reflejado
    const originalSend = res.send;
    res.send = (body: any) => {
      if (typeof body === 'string') {
        const reflectedXss = this.detectReflectedXss(body, req);
        if (reflectedXss) {
          this.logger.error('XSS REFLEJADO DETECTADO');
          this.logger.error(`Endpoint: ${req.method} ${req.originalUrl}`);
          this.logger.error(`Payload reflejado en respuesta`);
        }
      }
      return originalSend.call(res, body);
    };

    // 4. Detectar time-based attacks (respuestas lentas)
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      if (duration > 3000) {
        this.logger.warn(
          `Respuesta lenta (${duration}ms) - Posible Time-Based Attack`,
        );
        this.logger.warn(`Endpoint: ${req.method} ${req.originalUrl}`);
      }
    });

    next();
  }

  private detectThreats(req: Request): string[] {
    const threats: string[] = [];
    const inputs = { ...req.body, ...req.query, ...req.params };

    const patterns = [
      { regex: /(\-\-|\|\||\&\&)/, name: 'SQL Injection' },
      { regex: /<script|javascript:|onerror=|onload=/, name: 'XSS' },
      { regex: /\.\.\/|\.\.\\/, name: 'Path Traversal' },
      { regex: /\$\{/, name: 'Command Injection' },
      {
        regex: /\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|UNION\s+SELECT)\b/i,
        name: 'SQL Keyword',
      },
      { regex: /'\s*OR\s*'1'\s*=\s*'1/i, name: 'Auth Bypass' },
      { regex: /\badmin'\s*--/i, name: 'SQL Comment Injection' },
      { regex: /sleep\([0-9]+\)/i, name: 'Time-Based SQLi' },
    ];

    for (const [key, value] of Object.entries(inputs)) {
      if (typeof value === 'string') {
        const activePatterns = this.relaxedFields.has(key)
          ? patterns.filter((pattern) => pattern.name !== 'SQL Injection')
          : patterns;

        for (const pattern of activePatterns) {
          if (pattern.regex.test(value)) {
            threats.push(
              `${pattern.name} en campo '${key}': ${value.substring(0, 50)}`,
            );
          }
        }
      }
    }

    return threats;
  }

  private sanitizeForLog(input: Record<string, unknown>): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(input)) {
      if (this.sensitiveFields.has(key)) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  private detectReflectedXss(body: string, req: Request): boolean {
    const inputs = { ...req.body, ...req.query, ...req.params };
    for (const value of Object.values(inputs)) {
      if (typeof value === 'string') {
        const maliciousPatterns = [
          '<script',
          'javascript:',
          'onerror=',
          'onload=',
        ];
        if (
          maliciousPatterns.some((p) => value.includes(p)) &&
          body.includes(value)
        ) {
          return true;
        }
      }
    }
    return false;
  }
}
