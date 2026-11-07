import {
  ExecutionContext,
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { DataSource } from 'typeorm';
import { ActiveAdminGuard } from './active-admin.guard';

function context(user?: { id_usuario: number; rol: number }): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ user }) }),
  } as unknown as ExecutionContext;
}

describe('ActiveAdminGuard', () => {
  let query: jest.Mock<Promise<{ id_usuario: number }[]>, [string, number[]]>;
  let guard: ActiveAdminGuard;
  beforeEach(() => {
    query = jest.fn<Promise<{ id_usuario: number }[]>, [string, number[]]>();
    guard = new ActiveAdminGuard({ query } as unknown as DataSource);
  });

  it('exige administrador autenticado antes de consultar la base', async () => {
    for (const user of [
      undefined,
      { id_usuario: 1, rol: 1 },
      { id_usuario: 1, rol: 2 },
      { id_usuario: 0, rol: 3 },
      { id_usuario: 1.5, rol: 3 },
    ]) {
      await expect(guard.canActivate(context(user))).rejects.toBeInstanceOf(
        ForbiddenException,
      );
    }
    expect(query).not.toHaveBeenCalled();
  });

  it('comprueba en la base la cuenta actual, con el identificador como parámetro', async () => {
    query.mockResolvedValue([{ id_usuario: 42 }]);
    await expect(
      guard.canActivate(context({ id_usuario: 42, rol: 3 })),
    ).resolves.toBe(true);
    expect(query.mock.calls[0][1]).toEqual([42]);
  });

  it('rechaza una cuenta desactivada, eliminada o con rol cambiado aunque el JWT diga Admin', async () => {
    query.mockResolvedValue([]);
    await expect(
      guard.canActivate(context({ id_usuario: 42, rol: 3 })),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('un fallo al verificar permisos cierra el acceso sin devolver el error de la base', async () => {
    query.mockRejectedValue(new Error('detalle privado de conexión'));
    await expect(
      guard.canActivate(context({ id_usuario: 42, rol: 3 })),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
  });
});
