import { IsNotEmpty, IsEmail, IsOptional } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty({ message: 'Todos los campos son obligatorios' })
  nombre: string;

  @IsNotEmpty({ message: 'Todos los campos son obligatorios' })
  aPaterno: string;

  @IsNotEmpty({ message: 'Todos los campos son obligatorios' })
  aMaterno: string;

  @IsEmail({}, { message: 'El correo no tiene un formato válido' })
  @IsNotEmpty({ message: 'Todos los campos son obligatorios' })
  email?: string;

  @IsNotEmpty({ message: 'Todos los campos son obligatorios' })
  telefono?: string;

  @IsNotEmpty({ message: 'Todos los campos son obligatorios' })
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
