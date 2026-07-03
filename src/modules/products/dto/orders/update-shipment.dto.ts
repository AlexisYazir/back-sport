import { Type } from 'class-transformer';
import {
  IsDateString,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  MaxLength,
  Min,
} from 'class-validator';

export class UpdateShipmentDto {
  @IsString()
  @IsIn(['pendiente', 'preparando', 'enviado', 'en transito', 'en_transito', 'entregado', 'incidencia'])
  estado:
    | 'pendiente'
    | 'preparando'
    | 'enviado'
    | 'en transito'
    | 'en_transito'
    | 'entregado'
    | 'incidencia';

  @IsOptional()
  @IsString()
  @MaxLength(80)
  tracking_number?: string;

  @IsOptional()
  @IsString()
  @MaxLength(80)
  paqueteria?: string;

  @IsOptional()
  @IsString()
  @MaxLength(120)
  ubicacion?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  comentario?: string;

  @IsOptional()
  @IsDateString()
  fecha_entrega_estimada?: string;
}

export class ConfirmDeliveryCodeDto {
  @IsString()
  @MaxLength(20)
  codigo: string;
}

export class CreateReturnItemDto {
  @Type(() => Number)
  @IsInt()
  @Min(1)
  id_variante: number;

  @Type(() => Number)
  @IsInt()
  @Min(1)
  cantidad: number;

  @IsOptional()
  @IsString()
  @MaxLength(180)
  motivo?: string;
}
