import { IsNotEmpty, IsString, IsNumber } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateCategorieDto {
  @IsNotEmpty({ message: 'El id de la categoria es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  id_categoria: number;

  @IsNotEmpty({ message: 'El nombre de categoria es obligatorio' })
  @IsString()
  nombre: string;

  @Type(() => Number)
  @IsNumber()
  id_padre: number;
}
