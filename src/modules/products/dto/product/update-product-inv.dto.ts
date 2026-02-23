import { IsNotEmpty, IsNumber, IsBoolean } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateProductInvDto {
  @IsNotEmpty({ message: 'El id de producto es obligatorio' })
  @IsNumber()
  @Type(() => Number)
  id_producto: number;

  @IsBoolean({ message: 'El estado debe ser booleano' })
  @Type(() => Boolean)
  estado: boolean;
}
