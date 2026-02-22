import { IsNotEmpty, IsString, IsNumber } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateMarcaDto {
  @IsNotEmpty({ message: 'El id de la marca es obligatorio' })
  @Type(() => Number)
  @IsNumber()
  id_marca: number;

  @IsNotEmpty({ message: 'El nombre de marca es obligatorio' })
  @IsString()
  nombre: string;

  @IsNotEmpty({ message: 'El sitio web es obligatorio' })
  @IsString()
  sitio_web: string;
}
