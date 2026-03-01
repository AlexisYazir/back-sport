import { IsNotEmpty, IsString } from 'class-validator';

export class CreateMarcaDto {
  @IsNotEmpty({ message: 'El nombre de marca es obligatorio' })
  @IsString()
  nombre: string;

  @IsNotEmpty({ message: 'La imagen es obligatoria' })
  @IsString()
  imagen: string;
}
