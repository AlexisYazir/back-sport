import { Transform, Type } from 'class-transformer';
import {
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Length,
  Max,
  Min,
} from 'class-validator';
import type { ReviewModerationAction } from '../../types/review-moderation.types';

export class ReviewReportsQueryDto {
  @IsIn(['pendiente', 'atendido', 'todos'])
  estado: 'pendiente' | 'atendido' | 'todos' = 'pendiente';

  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(2147483647)
  page = 1;

  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit = 20;
}

export class ModerateReviewDto {
  @IsIn(['conservar', 'retirar', 'restaurar'])
  accion: ReviewModerationAction;

  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  @IsString()
  @Length(1, 1000)
  motivo: string;

  @IsInt()
  @Min(0)
  @Max(2147483646)
  revision_esperada: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(2147483647)
  id_mensaje?: number;
}
