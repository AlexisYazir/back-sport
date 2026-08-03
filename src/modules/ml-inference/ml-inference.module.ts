import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MlInferenceService } from './ml-inference.service';

@Module({
  imports: [ConfigModule],
  providers: [MlInferenceService],
  exports: [MlInferenceService],
})
export class MlInferenceModule {}
