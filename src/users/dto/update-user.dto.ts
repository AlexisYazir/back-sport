import { IsNotEmpty, IsEmail, IsOptional, IsNumber } from 'class-validator';

export class UpdateUserDto {
  @IsOptional()
  @IsNumber()
  id_usuario?: number;

  @IsOptional()
  @IsNotEmpty()
  nombre?: string;

  @IsOptional()
  @IsNotEmpty()
  aPaterno?: string;

  @IsOptional()
  @IsNotEmpty()
  aMaterno?: string;

  @IsEmail()
  @IsOptional()
  email?: string;

  @IsOptional()
  telefono?: string;

  @IsOptional()
  @IsNotEmpty()
  passw?: string;

  @IsOptional()
  rol?: number;

  @IsOptional()
  token_expiracion?: Date;

  @IsOptional()
  fecha_creacion?: Date;

  @IsOptional()
  fecha_actualizacion?: Date;

  @IsOptional()
  ubicacion?: number;
}
