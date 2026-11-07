import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  ServiceUnavailableException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import type { AuthenticatedRequest } from './authenticated-request';

/** Revalida el permiso actual: un JWT anterior a una baja de rol no lo conserva. */
@Injectable()
export class ActiveAdminGuard implements CanActivate {
  constructor(
    @InjectDataSource('readerConnection')
    private readonly dataSource: DataSource,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const { user } = context.switchToHttp().getRequest<AuthenticatedRequest>();
    if (
      !user ||
      user.rol !== 3 ||
      !Number.isSafeInteger(user.id_usuario) ||
      user.id_usuario <= 0
    ) {
      throw new ForbiddenException(
        'Se requiere una cuenta administradora activa',
      );
    }

    let users: { id_usuario: number }[];
    try {
      users = await this.dataSource.query<{ id_usuario: number }[]>(
        'SELECT id_usuario FROM core.users WHERE id_usuario = $1 AND rol = 3 AND activo = 1 LIMIT 1',
        [user.id_usuario],
      );
    } catch {
      throw new ServiceUnavailableException(
        'No fue posible comprobar el acceso administrativo',
      );
    }
    if (users.length !== 1 || users[0].id_usuario !== user.id_usuario) {
      throw new ForbiddenException(
        'Se requiere una cuenta administradora activa',
      );
    }
    return true;
  }
}
