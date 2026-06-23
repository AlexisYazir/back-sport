import { Type } from 'class-transformer';
import {
  ArrayMinSize,
  IsArray,
  IsIn,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
  Min,
  ValidateNested,
} from 'class-validator';

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

export class CreateReturnDto {
  @Type(() => Number)
  @IsInt()
  @Min(1)
  id_orden: number;

  @IsString()
  @IsNotEmpty()
  @MaxLength(120)
  motivo: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  comentario?: string;

  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => CreateReturnItemDto)
  items: CreateReturnItemDto[];
}

export class UpdateReturnStatusDto {
  @IsString()
  @IsIn(['solicitada', 'aprobada', 'rechazada', 'recibida', 'reembolsada', 'cerrada'])
  estado: 'solicitada' | 'aprobada' | 'rechazada' | 'recibida' | 'reembolsada' | 'cerrada';

  @IsOptional()
  @IsString()
  @MaxLength(500)
  comentario?: string;
}
