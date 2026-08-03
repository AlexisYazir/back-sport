import { Module } from '@nestjs/common';
import { ReportsController } from './reports.controller';
import { SalesReportsService } from './sales-reports.service';
import { DemandForecastModule } from '../demand-forecast/demand-forecast.module';

@Module({
  imports: [DemandForecastModule],
  controllers: [ReportsController],
  providers: [SalesReportsService],
})
export class ReportsModule {}
