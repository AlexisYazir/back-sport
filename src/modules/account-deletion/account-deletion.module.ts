import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { resolve } from 'node:path';
import { AccountDeletionController } from './account-deletion.controller';
import {
  AccountDeletionService,
  DELETION_LEDGER,
} from './account-deletion.service';
import { AccountDeletionDataService } from './account-deletion-data.service';
import { AccountDeletionAccessModule } from './account-deletion-access.module';
import { AccountDeletionBootstrapService } from './account-deletion-bootstrap.service';
import { DeletionSecrets } from './deletion-secrets';
import { DeletionRecoveryGate } from './deletion-recovery-gate';
import {
  AccountDeletionMutationGuard,
  DeletionRecoveryGuard,
  DeletionNoStoreInterceptor,
} from './account-deletion.guards';
import { FileDeletionLedger } from './ledger/file-deletion-ledger';
import type { DeletionLedger } from './ledger/deletion-ledger';
import { ActiveAdminGuard } from '../../services/auth/active-admin.guard';
import { RolesGuard } from '../../services/auth/roles.guard';
import { MailModule } from '../../services/mail/mail.module';

@Module({
  imports: [ConfigModule, MailModule, AccountDeletionAccessModule],
  controllers: [AccountDeletionController],
  providers: [
    AccountDeletionService,
    AccountDeletionDataService,
    DeletionSecrets,
    AccountDeletionBootstrapService,
    AccountDeletionMutationGuard,
    DeletionRecoveryGuard,
    DeletionNoStoreInterceptor,
    ActiveAdminGuard,
    RolesGuard,
    {
      provide: DELETION_LEDGER,
      inject: [ConfigService],
      useFactory: (config: ConfigService): DeletionLedger | null => {
        if (config.get<string>('ACCOUNT_DELETION_ENABLED') !== 'true')
          return null;
        const key = config.get<string>('ACCOUNT_DELETION_LEDGER_SECRET') ?? '';
        if (
          !/^[a-f\d]{64}$/i.test(key) ||
          ['JWT_SECRET', 'JWT_REFRESH_SECRET', 'ACCOUNT_DELETION_SECRET'].some(
            (name) =>
              key.toLowerCase() === config.get<string>(name)?.toLowerCase(),
          )
        )
          throw new Error('ACCOUNT_DELETION_LEDGER_KEY_REQUIRED');
        return new FileDeletionLedger({
          directory: config.getOrThrow<string>('ACCOUNT_DELETION_LEDGER_DIR'),
          repositoryRoot: resolve(__dirname, '../../..'),
          hmacKey: Buffer.from(key, 'hex'),
        });
      },
    },
    {
      provide: DeletionRecoveryGate,
      inject: [ConfigService, DELETION_LEDGER],
      useFactory: (config: ConfigService, ledger: DeletionLedger | null) =>
        new DeletionRecoveryGate(
          config.get<string>('ACCOUNT_DELETION_ENABLED') === 'true',
          ledger ?? undefined,
        ),
    },
  ],
  exports: [
    AccountDeletionBootstrapService,
    DeletionRecoveryGate,
    DeletionRecoveryGuard,
  ],
})
export class AccountDeletionModule {}
