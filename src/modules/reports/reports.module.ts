import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ReportsController } from './reports.controller';
import { SalesReportsService } from './sales-reports.service';
import { DataMiningReportsService } from './data-mining-reports.service';
import { ProductRecommendationsController } from './product-recommendations.controller';
import { MlTrainingService } from './ml-training.service';
import { MlTrainingScheduleEntity } from './entities/ml-training-schedule.entity';
import { MlModelRunEntity } from './entities/ml-model-run.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature(
      [MlTrainingScheduleEntity, MlModelRunEntity],
      'adminConnection',
    ),
  ],
  controllers: [ReportsController, ProductRecommendationsController],
  providers: [SalesReportsService, DataMiningReportsService, MlTrainingService],
})
export class ReportsModule {}
