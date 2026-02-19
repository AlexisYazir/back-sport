import { IsNotEmpty, IsString } from 'class-validator';

export class CreateAttributeDto {
  @IsNotEmpty({ message: 'El nombre de atributo es obligatoria' })
  @IsString()
  nombre: string;
}
