import {
  IsNotEmpty,
  IsString,
  IsNumber,
  IsArray,
  IsOptional,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CreateProductVariantDto {
  @IsNotEmpty({ message: 'El id de producto es obligatorio' })
  @Type(() => Number)
  id_producto: number;

  @IsNotEmpty({ message: 'La codigo de producto es obligatoria' })
  @IsString()
  sku: string;

  @IsNotEmpty({ message: 'El precio es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  precio: number;

  @IsNotEmpty({ message: 'El stock es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  stock: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  imagenes?: string[];
}
