import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { Observable, catchError, tap, throwError } from 'rxjs';
import { CloudflareLogService } from '../services/cloudflare-log.service';

@Injectable()
export class HttpAuditInterceptor implements NestInterceptor {
  private readonly logger = new Logger(HttpAuditInterceptor.name);

  constructor(private readonly logService: CloudflareLogService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    if (context.getType() !== 'http') {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const startedAt = Date.now();

    return next.handle().pipe(
      tap(() => {
        const statusCode = response.statusCode ?? 200;
        this.logService
          .registerHttpEvent(request, statusCode, Date.now() - startedAt)
          .catch((error) =>
            this.logger.error(`No se pudo registrar log HTTP: ${error instanceof Error ? error.message : String(error)}`),
          );
      }),
      catchError((error) => {
        const statusCode = error?.status ?? response?.statusCode ?? 500;
        this.logService
          .registerHttpEvent(request, statusCode, Date.now() - startedAt, error)
          .catch((logError) =>
            this.logger.error(`No se pudo registrar log HTTP con error: ${logError instanceof Error ? logError.message : String(logError)}`),
          );

        return throwError(() => error);
      }),
    );
  }
}
