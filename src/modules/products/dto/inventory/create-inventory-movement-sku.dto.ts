import {
  IsNotEmpty,
  IsString,
  IsNumber,
  IsOptional,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CreateInventoryMovementSkuDto {
  @IsNotEmpty({ message: 'El SKU es obligatorio' })
  @IsString()
  sku: string; // SKU en lugar de id_variante

  @IsNotEmpty({ message: 'El tipo de movimiento es obligatorio' })
  @IsString()
  tipo: string;

  @IsNotEmpty({ message: 'La cantidad es obligatoria' })
  @Type(() => Number)
  @IsNumber()
  @Min(1, { message: 'La cantidad debe ser mayor a 0' })
  cantidad: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  costo_unitario?: number;

  @IsOptional()
  @IsString()
  referencia_tipo?: string;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  referencia_id?: number;
}
