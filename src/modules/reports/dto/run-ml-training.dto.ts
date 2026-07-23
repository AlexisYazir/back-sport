import { ArrayNotEmpty, IsArray, IsIn, IsOptional } from 'class-validator';
import { MlPipeline } from '../entities/ml-training-schedule.entity';

export class RunMlTrainingDto {
  @IsOptional()
  @IsArray()
  @ArrayNotEmpty()
  @IsIn(['demand', 'recommendation', 'clustering'], { each: true })
  pipelines?: MlPipeline[];
}
