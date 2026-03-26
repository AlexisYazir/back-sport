import {
  IsDateString,
  IsIn,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
} from 'class-validator';

export class CreateRetentionPolicyDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @IsOptional()
  @IsIn(['full', 'critical', 'all'])
  type?: 'full' | 'critical' | 'all';

  @IsIn(['daily', 'weekly', 'datetime'])
  scheduleType: 'daily' | 'weekly' | 'datetime';

  @Matches(/^([01]\d|2[0-3]):([0-5]\d)$/, {
    message: 'time must use HH:mm format',
  })
  time: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(6)
  dayOfWeek?: number;

  @IsOptional()
  @IsDateString()
  runAt?: string;

  @IsInt()
  @Min(1)
  retentionDays: number;
}
