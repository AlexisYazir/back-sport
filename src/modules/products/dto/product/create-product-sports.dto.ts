import { Type } from 'class-transformer';
import {
  ArrayUnique,
  IsArray,
  IsInt,
  IsNotEmpty,
  IsOptional,
} from 'class-validator';

export class CreateProductSportsDto {
  @IsNotEmpty({ message: 'El producto es obligatorio' })
  @Type(() => Number)
  @IsInt({ message: 'El id del producto debe ser un numero entero' })
  id_producto: number;

  @IsOptional()
  @IsArray({ message: 'Los deportes deben enviarse en una lista' })
  @ArrayUnique({ message: 'No repitas deportes en la seleccion' })
  @Type(() => Number)
  @IsInt({ each: true, message: 'Cada deporte debe ser un numero entero' })
  ids_deportes: number[];
}
