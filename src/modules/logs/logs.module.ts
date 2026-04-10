import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { ConfigModule } from '@nestjs/config';
import { MailModule } from '../../services/mail/mail.module';
import { R2StorageService } from '../backups/services/r2-storage.service';
import { LogsController } from './logs.controller';
import { HttpAuditInterceptor } from './interceptors/http-audit.interceptor';
import { CloudflareLogService } from './services/cloudflare-log.service';

@Module({
  imports: [ConfigModule, MailModule],
  controllers: [LogsController],
  providers: [
    R2StorageService,
    CloudflareLogService,
    {
      provide: APP_INTERCEPTOR,
      useClass: HttpAuditInterceptor,
    },
  ],
})
export class LogsModule {}
