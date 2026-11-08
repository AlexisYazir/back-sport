import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  ServiceUnavailableException,
  CallHandler,
  NestInterceptor,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { DeletionRecoveryGate } from './deletion-recovery-gate';

@Injectable()
export class DeletionNoStoreInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler) {
    const res = context.switchToHttp().getResponse<Response>();
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    return next.handle();
  }
}

@Injectable()
export class AccountDeletionMutationGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    if (!req.is('application/json'))
      throw new ForbiddenException('Se requiere una solicitud JSON');
    const cookie = req.headers.cookie ?? '';
    const bearer = /^Bearer\s+\S+$/i.test(req.headers.authorization ?? '');
    const principal = (req as Request & { user?: unknown }).user;
    const receiptOnly = /\/requests\/[a-f\d-]+\/result$/.test(req.path);
    if (
      req.headers.origin ||
      (/(?:^|;\s*)sc_(?:access|refresh)_token=/.test(cookie) &&
        !(bearer && principal) &&
        !receiptOnly)
    ) {
      const origins = new Set([
        'http://localhost:4200',
        'http://localhost:8081',
        'http://localhost:19006',
        'https://sport-center-sitie.netlify.app',
      ]);
      const configured = this.config.get<string>('FRONTEND_URL');
      if (configured) {
        try {
          const target = new URL(configured);
          if (
            !['http:', 'https:'].includes(target.protocol) ||
            target.username ||
            target.password
          )
            throw new Error('Invalid origin');
          origins.add(target.origin);
        } catch {
          throw new ForbiddenException();
        }
      }
      if (!req.headers.origin || !origins.has(req.headers.origin))
        throw new ForbiddenException('Origen de solicitud no permitido');
    }
    return true;
  }
}

@Injectable()
export class DeletionRecoveryGuard implements CanActivate {
  constructor(private readonly gate: DeletionRecoveryGate) {}
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    // The restricted receipt reveals only the operation result and remains usable after a network failure.
    if (
      req.method === 'POST' &&
      /^\/users\/account-deletion\/requests\/[a-f\d-]+\/result$/.test(req.path)
    )
      return true;
    try {
      this.gate.assertApplicationReady();
    } catch {
      throw new ServiceUnavailableException(
        'Recuperación de datos pendiente de verificación',
      );
    }
    return true;
  }
}
