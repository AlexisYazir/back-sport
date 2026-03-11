import {
  IsString,
  IsOptional,
  IsNumber,
  IsBoolean,
  IsArray,
} from 'class-validator';

export class CreateFaqDto {
  @IsString()
  pregunta: string;

  @IsString()
  respuesta: string;

  @IsOptional()
  @IsNumber()
  orden?: number;

  @IsOptional()
  @IsString()
  seccion?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  palabras_clave?: string[];

  @IsOptional()
  @IsBoolean()
  activo?: boolean;

  @IsOptional()
  @IsBoolean()
  destacado?: boolean;
}
