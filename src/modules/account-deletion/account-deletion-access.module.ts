import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AccountDeletionAccessService } from './account-deletion-access.service';

@Module({
  imports: [ConfigModule],
  providers: [AccountDeletionAccessService],
  exports: [AccountDeletionAccessService],
})
export class AccountDeletionAccessModule {}
