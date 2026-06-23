import { Type } from 'class-transformer';
import { IsInt, Max, Min } from 'class-validator';

export class AddCartItemDto {
  @Type(() => Number)
  @IsInt({ message: 'La variante debe ser válida' })
  @Min(1, { message: 'La variante debe ser válida' })
  id_variante: number;

  @Type(() => Number)
  @IsInt({ message: 'La cantidad debe ser un número entero' })
  @Min(1, { message: 'La cantidad mínima es 1' })
  @Max(99, { message: 'La cantidad máxima por producto es 99' })
  cantidad: number;
}
