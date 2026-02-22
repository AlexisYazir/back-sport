import { IsNotEmpty, IsString } from 'class-validator';

export class CreateMarcaDto {
  @IsNotEmpty({ message: 'El nombre de marca es obligatorio' })
  @IsString()
  nombre: string;

  @IsNotEmpty({ message: 'El sitio web es obligatorio' })
  @IsString()
  sitio_web: string;
}
