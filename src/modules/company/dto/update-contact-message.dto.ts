import { IsOptional, IsBoolean, IsNumber } from 'class-validator';

export class UpdateContactMessageDto {
  @IsOptional()
  @IsBoolean()
  leido?: boolean;

  @IsOptional()
  @IsBoolean()
  respondido?: boolean;

  @IsOptional()
  @IsNumber()
  id_usuario_responde?: number;
}
