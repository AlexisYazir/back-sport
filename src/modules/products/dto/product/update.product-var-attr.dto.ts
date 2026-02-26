import { IsNumber, IsString, IsArray, IsNotEmpty } from 'class-validator';
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
  @IsNotEmpty({ message: 'El SKU es obligatorio' })
  sku: string;

  @Type(() => Array)
  @IsArray()
  imagenes: string[];

  @IsNotEmpty({ message: '' })
  @Type(() => Number)
  @IsNumber()
  stock: number;

  @IsNotEmpty({ message: 'El precio es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  precio: number;
}

export interface UpdateProductVarAttResult {
  updated_variants: number;
}
