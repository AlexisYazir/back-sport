import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsDateString,
  IsIn,
  IsInt,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Max,
  MaxLength,
  Min,
} from 'class-validator';

export class CreatePromotionDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(120)
  nombre: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  descripcion?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  codigo?: string;

  @IsString()
  @IsIn(['porcentaje', 'monto_fijo', 'envio_gratis'])
  tipo: 'porcentaje' | 'monto_fijo' | 'envio_gratis';

  @Type(() => Number)
  @IsNumber()
  @Min(0)
  valor: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  descuento_maximo?: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  compra_minima?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  uso_maximo?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  uso_por_usuario?: number;

  @IsDateString()
  inicia_en: string;

  @IsDateString()
  termina_en: string;

  @IsOptional()
  @IsBoolean()
  activo?: boolean;
}

export class UpdatePromotionDto {
  @IsOptional()
  @IsString()
  @MaxLength(120)
  nombre?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  descripcion?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  codigo?: string;

  @IsOptional()
  @IsString()
  @IsIn(['porcentaje', 'monto_fijo', 'envio_gratis'])
  tipo?: 'porcentaje' | 'monto_fijo' | 'envio_gratis';

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  valor?: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  descuento_maximo?: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  compra_minima?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  uso_maximo?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  uso_por_usuario?: number;

  @IsOptional()
  @IsDateString()
  inicia_en?: string;

  @IsOptional()
  @IsDateString()
  termina_en?: string;

  @IsOptional()
  @IsBoolean()
  activo?: boolean;
}

export class UpdateShippingMethodDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  nombre?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  descripcion?: string;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  costo_base?: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  envio_gratis_desde?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  dias_min?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  dias_max?: number;

  @IsOptional()
  @IsBoolean()
  activo?: boolean;
}
