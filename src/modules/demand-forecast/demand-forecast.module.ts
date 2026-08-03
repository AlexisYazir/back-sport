import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MlInferenceModule } from '../ml-inference/ml-inference.module';
import { DemandForecastController } from './demand-forecast.controller';
import { DemandForecastService } from './demand-forecast.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([], 'adminConnection'),
    MlInferenceModule,
  ],
  controllers: [DemandForecastController],
  providers: [DemandForecastService],
  exports: [DemandForecastService],
})
export class DemandForecastModule {}
