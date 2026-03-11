import { IsNotEmpty, IsString, IsNumber } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateInventoryMovementDto {
  @IsNotEmpty({ message: 'El id variante es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  id_variante: number;

  @IsNotEmpty({ message: 'El tipo de movimiento es obligatorio' })
  @IsString()
  tipo: string;

  @IsNotEmpty({ message: 'La cantidad es obligatoria' })
  @Type(() => Number)
  @IsNumber()
  cantidad: number;

  @IsNotEmpty({ message: 'El costo unitario es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  costo_unitario: number;

  @IsNotEmpty({ message: 'El tipo de referencia es obligatorio' })
  @IsString()
  referencia_tipo: string;

  @IsNotEmpty({ message: 'El numero de referencia es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  referencia_id: number;
}
