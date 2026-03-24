/* eslint-disable */
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Logger } from '@nestjs/common';

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger()
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<number[]>(
      'roles',
      context.getHandler(),
    );

    if (!requiredRoles) return true;

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!requiredRoles.includes(user.rol)) {
      this.logger.warn('Acceso denegado mi pana')
      throw new ForbiddenException('Acceso denegado');
    }

    return true;
  }
}