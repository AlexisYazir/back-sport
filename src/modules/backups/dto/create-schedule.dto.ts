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

export class CreateScheduleDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @IsIn(['daily', 'weekly', 'datetime'])
  scheduleType: 'daily' | 'weekly' | 'datetime';

  @IsOptional()
  @Matches(/^([01]\d|2[0-3]):([0-5]\d)$/, {
    message: 'time must use HH:mm format',
  })
  time?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(6)
  dayOfWeek?: number;

  @IsOptional()
  @IsDateString()
  runAt?: string;

  @IsOptional()
  @IsIn(['full', 'critical', 'vacuum'])
  type?: 'full' | 'critical' | 'vacuum';

  @IsOptional()
  @IsInt()
  @Min(1)
  retentionDays?: number;
}
