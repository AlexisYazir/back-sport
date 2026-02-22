import { IsNotEmpty, IsString, IsNumber } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateCategorieDto {
  @IsNotEmpty({ message: 'El nombre de categoria es obligatorio' })
  @IsString()
  nombre: string;

  @Type(() => Number)
  @IsNumber()
  id_padre: number;
}
