import {
  IsNotEmpty,
  IsString,
  IsNumber,
  IsArray,
  IsObject,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CreateProductVariantDto {
  @IsNotEmpty({ message: 'El id de producto es obligatorio' })
  @Type(() => Number)
  id_producto: number;

  @IsNotEmpty({ message: 'El codigo de producto es obligatorio' })
  @IsString()
  sku: string;

  @IsNotEmpty({ message: 'El precio es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  precio: number;

  @IsNotEmpty({ message: 'Las imagenes son obligatorias' })
  @IsArray()
  @IsString({ each: true })
  imagenes: string[];

  @IsNotEmpty({ message: 'Los atributos son obligatorios' })
  @IsObject()
  atributos: Record<string, any>;
}
