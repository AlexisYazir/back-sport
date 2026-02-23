import { IsNotEmpty, IsString, IsNumber, IsOptional } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateCategorieDto {
  @IsNotEmpty({ message: 'El nombre de categoria es obligatorio' })
  @IsString()
  nombre: string;

  @IsOptional() // ← Permite que sea opcional
  @Type(() => Number)
  @IsNumber()
  id_padre?: number | null; // ← Puede ser número o null
}
