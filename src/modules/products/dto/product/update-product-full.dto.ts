import { IsNumber, IsString } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateProductFullDto {
  @Type(() => Number)
  @IsNumber()
  id_producto: number;

  @Type(() => Number)
  @IsNumber()
  id_marca: number;

  @Type(() => Number)
  @IsNumber()
  id_categoria: number;

  @Type(() => String)
  @IsString()
  nombre: string;

  @Type(() => String)
  @IsString()
  descripcion: string;
}

export interface UpdateProductResult {
  updated_products: number;
  updated_variants: number;
  updated_attributes: number;
}
