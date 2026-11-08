import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource, EntityManager } from 'typeorm';
import { User } from '../users/entities/user.entity';

export const DELETION_LOCK_NAMESPACE = 193589;

/** Shared with deletion, so an in-flight login cannot create a surviving session. */
@Injectable()
export class AccountDeletionAccessService {
  constructor(
    @InjectDataSource('editorConnection') private readonly source: DataSource,
    private readonly config: ConfigService,
  ) {}

  get enabled(): boolean {
    return this.config.get<string>('ACCOUNT_DELETION_ENABLED') === 'true';
  }

  async assertAllowed(
    id: number,
    manager = this.source.manager,
  ): Promise<void> {
    if (!this.enabled) return;
    const rows = await manager.query<{ state: string }[]>(
      'SELECT state FROM core.account_deletion_accounts WHERE user_id=$1',
      [id],
    );
    if (rows.length !== 1 || rows[0].state !== 'active')
      throw new UnauthorizedException('La cuenta ya no está disponible');
  }

  async withAccountLock<T>(
    id: number,
    work: (manager: EntityManager, user: User) => Promise<T>,
    manager = this.source.manager,
  ): Promise<T> {
    const run = async (current: EntityManager): Promise<T> => {
      if (this.enabled) {
        await current.query('SELECT pg_advisory_xact_lock($1,$2)', [
          DELETION_LOCK_NAMESPACE,
          id,
        ]);
        await this.assertAllowed(id, current);
      }
      const user = await current
        .getRepository(User)
        .findOneBy({ id_usuario: id });
      if (!user)
        throw new UnauthorizedException('La cuenta ya no está disponible');
      return work(current, user);
    };
    if (!this.enabled || manager.queryRunner?.isTransactionActive)
      return run(manager);
    return manager.transaction(run);
  }

  async invalidateChallenges(
    id: number,
    manager: EntityManager,
  ): Promise<void> {
    if (!this.enabled) return;
    await manager.query(
      'SELECT core.invalidate_account_deletion_challenges($1)',
      [id],
    );
  }
}
