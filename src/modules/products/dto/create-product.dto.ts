import {
  IsNotEmpty,
  IsString,
  IsNumber,
  IsArray,
  IsOptional,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CreateProductDto {
  @IsNotEmpty({ message: 'El nombre es obligatorio' })
  @IsString()
  nombre: string;

  @IsNotEmpty({ message: 'La categoría es obligatoria' })
  @Type(() => Number)
  @IsNumber()
  categoria: number;

  @IsNotEmpty({ message: 'La marca es obligatoria' })
  @Type(() => Number)
  @IsNumber()
  marca: number;

  @IsNotEmpty({ message: 'La descripción es obligatoria' })
  @IsString()
  descripcion: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  imagenes?: string[];
}
