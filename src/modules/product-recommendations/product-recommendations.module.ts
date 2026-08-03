import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MlInferenceModule } from '../ml-inference/ml-inference.module';
import { ProductRecommendationsController } from './product-recommendations.controller';
import { ProductRecommendationsService } from './product-recommendations.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([], 'readerConnection'),
    MlInferenceModule,
  ],
  controllers: [ProductRecommendationsController],
  providers: [ProductRecommendationsService],
})
export class ProductRecommendationsModule {}
