import {
  IsNotEmpty,
  IsEmail,
  IsOptional,
  IsNumber,
  MinLength,
} from 'class-validator';

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
  @IsNumber()
  activo?: number;

  @IsOptional()
  telefono?: string;

  // *** NUEVO: Campo para contraseña actual ***
  @IsOptional()
  @IsNotEmpty()
  contrasenaActual?: string;

  // *** CAMBIADO: passw ahora es la nueva contraseña ***
  @IsOptional()
  @IsNotEmpty()
  @MinLength(12, {
    message: 'La nueva contraseña debe tener al menos 12 caracteres',
  })
  passw?: string; // Esta es la NUEVA contraseña

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
