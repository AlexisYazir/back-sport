import { IsString, IsOptional, IsEmail, IsUrl, IsArray } from 'class-validator';

export class CreateCompanyDto {
  @IsString()
  nombre: string;

  @IsOptional()
  @IsString()
  rfc?: string;

  @IsOptional()
  @IsString()
  telefono?: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsUrl()
  sitio_web?: string;

  @IsOptional()
  id_direccion?: number;

  @IsOptional()
  @IsUrl()
  facebook?: string;

  @IsOptional()
  @IsUrl()
  instagram?: string;

  @IsOptional()
  @IsUrl()
  twitter?: string;

  @IsOptional()
  @IsUrl()
  tiktok?: string;

  @IsOptional()
  @IsUrl()
  youtube?: string;

  @IsOptional()
  @IsString()
  regimen_fiscal?: string;

  @IsOptional()
  @IsUrl()
  logo_url?: string;

  @IsOptional()
  @IsString()
  horario_atencion?: string;

  @IsOptional()
  @IsString()
  mision?: string;

  @IsOptional()
  @IsString()
  vision?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  valores?: string[];

  @IsOptional()
  @IsString()
  mapa_ubicacion?: string;
}
