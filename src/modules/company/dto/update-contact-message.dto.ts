import { IsOptional, IsBoolean } from 'class-validator';

export class UpdateContactMessageDto {
  @IsOptional()
  @IsBoolean()
  leido?: boolean;

  @IsOptional()
  @IsBoolean()
  respondido?: boolean;
}
