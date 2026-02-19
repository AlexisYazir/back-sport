import { IsNotEmpty, IsString, IsNumber } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateVarAttributeValuesDto {
  @IsNotEmpty()
  @Type(() => Number)
  @IsNumber()
  id_variante: number;

  @IsNotEmpty()
  @Type(() => Number)
  @IsNumber()
  id_atributo: number;

  @IsNotEmpty()
  @IsString()
  valor: string;
}
