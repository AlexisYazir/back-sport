import { IsNumber, IsString, IsArray } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateProductVariantAttributeDto {
  @Type(() => Number)
  @IsNumber()
  id_producto: number;

  @Type(() => Number)
  @IsNumber()
  id_variante: number;

  @Type(() => String)
  @IsString()
  sku: string;

  @Type(() => Array)
  @IsArray()
  imagenes: string[];

  @Type(() => Number)
  @IsNumber()
  stock: number;

  @Type(() => Number)
  @IsNumber()
  precio: number;
}

export interface UpdateProductVarAttResult {
  updated_variants: number;
}
