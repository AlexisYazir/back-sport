import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CompanyController } from './company.controller';
import { CompanyService } from './company.service';
import { CompanyInfo } from './entities/company-info.entity';
import { Faq } from './entities/faq.entity';
import { ContactMessage } from './entities/contact-message.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature(
      [CompanyInfo, Faq, ContactMessage],
      'editorConnection',
    ),
    TypeOrmModule.forFeature(
      [CompanyInfo, Faq, ContactMessage],
      'readerConnection',
    ),
  ],
  controllers: [CompanyController],
  providers: [CompanyService],
  exports: [CompanyService],
})
export class CompanyModule {}
