import { ConfigModule } from '@nestjs/config';
import { MailService } from './mail.service';
import { Module } from '@nestjs/common';

@Module({
  imports: [ConfigModule],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
