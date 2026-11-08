import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
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
import { AccountDeletionActivationService } from './account-deletion-activation.service';
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
    AccountDeletionActivationService,
    DeletionSecrets,
    AccountDeletionBootstrapService,
    AccountDeletionMutationGuard,
    DeletionRecoveryGuard,
    DeletionNoStoreInterceptor,
    ActiveAdminGuard,
    RolesGuard,
    {
      provide: DELETION_LEDGER,
      inject: [AccountDeletionActivationService],
      useFactory: (
        activation: AccountDeletionActivationService,
      ): Promise<DeletionLedger | null> => activation.prepare(),
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
