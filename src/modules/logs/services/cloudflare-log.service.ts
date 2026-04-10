import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MailService } from '../../../services/mail/mail.service';
import { R2StorageService } from '../../backups/services/r2-storage.service';

type LogLevel = 'info' | 'warn' | 'error' | 'critical';

export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  module: string;
  event: string;
  data: Record<string, unknown>;
}

export interface LogQuery {
  date?: string;
  module?: string;
  level?: string;
  search?: string;
  page?: number;
  limit?: number;
}

@Injectable()
export class CloudflareLogService {
  private readonly logger = new Logger(CloudflareLogService.name);

  constructor(
    private readonly r2StorageService: R2StorageService,
    private readonly mailService: MailService,
    private readonly configService: ConfigService,
  ) {}

  async registerHttpEvent(
    request: any,
    statusCode: number,
    durationMs: number,
    error?: any,
  ): Promise<void> {
    const path = `${request?.originalUrl ?? request?.url ?? ''}`;
    if (!path || path.startsWith('/logs')) {
      return;
    }

    const moduleName = this.getModuleFromPath(path);
    const metadata = this.classifyEvent(request, statusCode, error);
    const email =
      request?.user?.email ??
      request?.body?.email ??
      request?.body?.correo ??
      request?.query?.email ??
      null;

    const entry: LogEntry = {
      id: this.createId(),
      timestamp: new Date().toISOString(),
      level: metadata.level,
      module: moduleName,
      event: metadata.event,
      data: {
        method: request?.method ?? 'GET',
        path,
        statusCode,
        durationMs,
        ip: request?.ip ?? request?.socket?.remoteAddress ?? null,
        userAgent: request?.headers?.['user-agent'] ?? null,
        email,
        userId: request?.user?.id_usuario ?? request?.user?.id ?? null,
        sessionId:
          request?.user?.sessionId ??
          request?.user?.session_id ??
          request?.session?.id ??
          request?.headers?.['x-session-id'] ??
          null,
        ...(error
          ? {
              error: {
                name: error?.name ?? 'Error',
                message: error?.message ?? 'Unexpected error',
              },
            }
          : {}),
      },
    };

    await this.appendLog(entry);

    if (entry.level === 'critical') {
      await this.sendCriticalAlert(entry).catch((mailError) =>
        this.logger.error(
          `No fue posible enviar la alerta crítica por correo: ${
            mailError instanceof Error ? mailError.message : String(mailError)
          }`,
        ),
      );
    }
  }

  async getAvailableDates(): Promise<string[]> {
    const objects = await this.r2StorageService.list('logs/');
    const dates = new Set<string>();

    objects.forEach((object) => {
      if (!object.Key) return;
      const match = object.Key.match(/^logs\/(\d{4}-\d{2}-\d{2})\//);
      if (match) {
        dates.add(match[1]);
      }
    });

    return Array.from(dates).sort((a, b) => b.localeCompare(a));
  }

  async getAvailableModules(date?: string): Promise<string[]> {
    const targetDate = date || (await this.getAvailableDates())[0];
    if (!targetDate) return [];

    const objects = await this.r2StorageService.list(`logs/${targetDate}/`);
    const modules = new Set<string>();

    objects.forEach((object) => {
      const key = object.Key ?? '';
      const match = key.match(/^logs\/\d{4}-\d{2}-\d{2}\/(.+)\.log$/);
      if (match && match[1] !== 'logs') {
        modules.add(match[1]);
      }
    });

    return Array.from(modules).sort((a, b) => a.localeCompare(b));
  }

  async getLogs(query: LogQuery): Promise<{
    items: LogEntry[];
    total: number;
    page: number;
    limit: number;
  }> {
    const dates = await this.getAvailableDates();
    const targetDate = query.date || dates[0];
    const page = Math.max(1, query.page || 1);
    const limit = Math.max(1, query.limit || 5000);

    if (!targetDate) {
      return { items: [], total: 0, page, limit };
    }

    const modules = query.module && query.module !== 'all'
      ? [query.module]
      : await this.getAvailableModules(targetDate);

    const entries: LogEntry[] = [];
    for (const moduleName of modules) {
      const key = `logs/${targetDate}/${moduleName}.log`;
      try {
        const content = await this.r2StorageService.downloadText(key);
        const lines = content
          .split('\n')
          .map((line) => line.trim())
          .filter(Boolean);

        lines.forEach((line) => {
          try {
            const parsed = JSON.parse(line) as LogEntry;
            entries.push(parsed);
          } catch {
            this.logger.warn(`No se pudo parsear una línea del log ${key}`);
          }
        });
      } catch {
        continue;
      }
    }

    const filtered = entries
      .filter((entry) => entry.module !== 'logs')
      .filter((entry) => !query.level || query.level === 'all' || entry.level === query.level)
      .filter((entry) => this.matchesSearch(entry, query.search))
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp));

    const start = (page - 1) * limit;
    return {
      items: filtered.slice(start, start + limit),
      total: filtered.length,
      page,
      limit,
    };
  }

  private async appendLog(entry: LogEntry): Promise<void> {
    const date = entry.timestamp.slice(0, 10);
    const key = `logs/${date}/${entry.module}.log`;

    let previousContent = '';
    try {
      previousContent = await this.r2StorageService.downloadText(key);
    } catch {
      previousContent = '';
    }

    const nextContent = previousContent
      ? `${previousContent.trimEnd()}\n${JSON.stringify(entry)}\n`
      : `${JSON.stringify(entry)}\n`;

    await this.r2StorageService.uploadText(key, nextContent, 'text/plain; charset=utf-8');
  }

  private matchesSearch(entry: LogEntry, search?: string): boolean {
    if (!search?.trim()) return true;
    const term = search.trim().toLowerCase();
    const haystack = JSON.stringify(entry).toLowerCase();
    return haystack.includes(term);
  }

  private getModuleFromPath(path: string): string {
    const segment = path.split('?')[0].split('/').filter(Boolean)[0] ?? 'system';
    return segment || 'system';
  }

  private classifyEvent(
    request: any,
    statusCode: number,
    error?: any,
  ): { event: string; level: LogLevel } {
    const path = `${request?.originalUrl ?? request?.url ?? ''}`;
    const method = `${request?.method ?? 'GET'}`.toUpperCase();
    const body = request?.body ?? {};

    if (path.includes('/users/login-user')) {
      return statusCode >= 400
        ? { event: 'inicio_de_sesion_fallido', level: 'warn' }
        : { event: 'inicio_de_sesion_exitoso', level: 'info' };
    }

    if (path.includes('/users/profile') && method === 'GET') {
      return { event: 'consulta_de_perfil', level: 'info' };
    }

    if (path.includes('/users/update-user') && (body?.rol || body?.id_rol)) {
      return { event: 'modificacion_de_roles_de_usuario', level: 'critical' };
    }

    if (
      path.includes('/products/update-product-variant') ||
      path.includes('/products/update-product-full') ||
      path.includes('/products/update-product-inventory') ||
      path.includes('/products/create-inventory-movement') ||
      path.includes('/products/inventory-movements/bulk')
    ) {
      return { event: 'modificacion_de_precios_o_inventario', level: 'critical' };
    }

    if (
      path.includes('/products/delete-product') ||
      path.includes('/products/delete-category') ||
      path.includes('/products/delete-marca')
    ) {
      return { event: 'eliminacion_de_productos_o_categorias', level: 'critical' };
    }

    if (statusCode === 403) {
      return { event: 'intento_de_acceso_a_ruta_admin_sin_permisos', level: 'error' };
    }

    if (
      statusCode === 401 &&
      (path.includes('/users/refresh-token') ||
        path.includes('/users/profile') ||
        path.includes('/users/logout'))
    ) {
      return { event: 'token_jwt_invalido_o_expirado', level: 'info' };
    }

    if (statusCode >= 500 || error?.name === 'QueryFailedError') {
      return { event: 'consulta_sql_con_errores', level: 'error' };
    }

    return { event: 'http_request', level: 'info' };
  }

  private async sendCriticalAlert(entry: LogEntry): Promise<void> {
    const destination =
      this.configService.get<string>('LOG_ALERT_EMAIL') ||
      this.configService.get<string>('EMAIL_USER');

    if (!destination) {
      return;
    }

    const subject = `[Sport Center] Alerta crítica: ${this.toTitleCase(entry.event)}`;
    const html = `
      <h2>Alerta crítica detectada</h2>
      <p>Se registró un evento crítico en el sistema.</p>
      <ul>
        <li><b>Módulo:</b> ${entry.module}</li>
        <li><b>Evento:</b> ${this.toTitleCase(entry.event)}</li>
        <li><b>Fecha:</b> ${entry.timestamp}</li>
        <li><b>Método:</b> ${entry.data.method ?? 'N/A'}</li>
        <li><b>Ruta:</b> ${entry.data.path ?? 'N/A'}</li>
        <li><b>Usuario:</b> ${entry.data.email ?? 'No identificado'}</li>
      </ul>
      <pre>${JSON.stringify(entry.data, null, 2)}</pre>
    `;

    await this.mailService.sendCriticalAlertEmail(destination, subject, html);
  }

  private toTitleCase(value: string): string {
    return value
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (char) => char.toUpperCase());
  }

  private createId(): string {
    return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  }
}
