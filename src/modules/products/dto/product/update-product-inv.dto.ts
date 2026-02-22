import { IsNotEmpty, IsNumber, Min, IsBoolean } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateProductInvDto {
  @IsNotEmpty({ message: 'El id de variante es obligatorio' })
  @Type(() => Number)
  id_variante: number;
  @IsNotEmpty({ message: 'El id de producto es obligatorio' })
  @Type(() => Number)
  id_producto: number;

  @Type(() => Number)
  @IsNumber({}, { message: 'El precio debe ser numérico' })
  @Min(0, { message: 'El precio no puede ser negativo' })
  precio: number;

  @Type(() => Number)
  @IsNumber({}, { message: 'El stock debe ser numérico' })
  @Min(1, { message: 'El stock debe ser mayor a 0' })
  stock: number;

  @IsBoolean({ message: 'El estado debe ser booleano' })
  @Type(() => Boolean)
  estado: boolean;
}
