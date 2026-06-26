import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsIn,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
  ValidateNested,
} from 'class-validator';

export class CheckoutAddressDto {
  @IsOptional()
  @IsString()
  @MaxLength(50)
  alias?: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(150)
  calle: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  numero?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  colonia?: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  ciudad: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  estado: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(10)
  codigo_postal: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  pais?: string;

  @IsOptional()
  @IsBoolean()
  principal?: boolean;
}

export class CheckoutCardDto {
  @IsOptional()
  @IsString()
  @MaxLength(60)
  alias?: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(120)
  titular: string;

  @IsString()
  @IsNotEmpty()
  @Matches(/^[\d\s-]{13,23}$/)
  numero: string;

  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(12)
  exp_mes: number;

  @Type(() => Number)
  @IsInt()
  @Min(2026)
  @Max(2100)
  exp_anio: number;

  @IsString()
  @IsNotEmpty()
  @Matches(/^\d{3,4}$/)
  cvv: string;

  @IsOptional()
  @IsBoolean()
  principal?: boolean;
}

export class CreateCheckoutOrderDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  id_direccion_envio?: number;

  @IsOptional()
  @ValidateNested()
  @Type(() => CheckoutAddressDto)
  direccion?: CheckoutAddressDto;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  id_metodo_envio?: number;

  @IsString()
  @IsIn(['mercado_pago'])
  metodo_pago: 'mercado_pago';

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  id_metodo_pago_usuario?: number;

  @IsOptional()
  @IsBoolean()
  guardar_tarjeta?: boolean;

  @IsOptional()
  @ValidateNested()
  @Type(() => CheckoutCardDto)
  tarjeta?: CheckoutCardDto;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  codigo_promocion?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  referencia_pago?: string;
}
