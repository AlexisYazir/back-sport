import { IsNotEmpty, IsNumber } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateInventoryDto {
  @IsNotEmpty({ message: 'El id variante es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  id_variante: number;

  @IsNotEmpty({ message: 'La stock es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  stock_actual: number;

  @IsNotEmpty({ message: 'El costo promedio es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  costo_promedio: number;
}
