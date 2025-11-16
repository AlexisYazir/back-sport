import { IsNotEmpty, IsEmail, IsOptional } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty()
  nombre: string;

  @IsOptional()
  aPaterno: string;

  @IsOptional()
  aMaterno: string;

  @IsEmail({}, { message: 'El correo no tiene un formato válido' })
  @IsOptional()
  email?: string;

  @IsOptional()
  telefono?: string;

  @IsNotEmpty()
  passw: string;

  @IsOptional()
  rol?: number;

  @IsOptional()
  activo?: number;

  @IsOptional()
  token_verificacion?: string;

  @IsOptional()
  token_expiracion?: Date;

  @IsOptional()
  intentos_token?: number;

  @IsOptional()
  fecha_creacion?: Date;

  @IsOptional()
  fecha_actualizacion?: Date;

  @IsOptional()
  email_verified?: number;

  @IsOptional()
  telefono_verified?: number;

  @IsOptional()
  google_id?: string;

  @IsOptional()
  ubicacion?: number;
}
