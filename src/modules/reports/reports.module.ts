import { Module } from '@nestjs/common';
import { ReportsController } from './reports.controller';
import { SalesReportsService } from './sales-reports.service';

@Module({
  controllers: [ReportsController],
  providers: [SalesReportsService],
})
export class ReportsModule {}
