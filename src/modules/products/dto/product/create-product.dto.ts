import { IsNotEmpty, IsString, IsNumber } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateProductDto {
  @IsNotEmpty({ message: 'El nombre es obligatorio' })
  @IsString()
  nombre: string;

  @IsNotEmpty({ message: 'La categoría es obligatoria' })
  @Type(() => Number)
  @IsNumber()
  id_categoria: number;

  @IsNotEmpty({ message: 'La marca es obligatoria' })
  @Type(() => Number)
  @IsNumber()
  id_marca: number;

  @IsNotEmpty({ message: 'La descripción es obligatoria' })
  @IsString()
  descripcion: string;
}
