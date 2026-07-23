import { Transform } from 'class-transformer';
import {
  ArrayNotEmpty,
  IsArray,
  IsBoolean,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
} from 'class-validator';
import { MlPipeline } from '../entities/ml-training-schedule.entity';

export class UpdateMlScheduleDto {
  @IsOptional()
  @IsString()
  @MaxLength(120)
  nombre?: string;

  @IsOptional()
  @Transform(({ value }) => Number(value))
  @IsInt()
  @Min(1)
  @Max(28)
  diaMes?: number;

  @IsOptional()
  @IsString()
  @Matches(/^([01]\d|2[0-3]):[0-5]\d$/)
  hora?: string;

  @IsOptional()
  @IsString()
  @MaxLength(80)
  zonaHoraria?: string;

  @IsOptional()
  @IsArray()
  @ArrayNotEmpty()
  @IsIn(['demand', 'recommendation', 'clustering'], { each: true })
  pipelines?: MlPipeline[];

  @IsOptional()
  @IsBoolean()
  activo?: boolean;
}
