import { Type } from 'class-transformer';
import {
  IsInt,
  IsNotEmpty,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
  MinLength,
} from 'class-validator';

export class CreateReviewDto {
  @IsNotEmpty({ message: 'El producto es obligatorio' })
  @Type(() => Number)
  @IsInt()
  @Min(1, { message: 'El producto debe ser válido' })
  id_producto: number;

  @IsNotEmpty({ message: 'La calificación es obligatoria' })
  @Type(() => Number)
  @IsInt()
  @Min(1, { message: 'La calificación mínima es 1' })
  @Max(5, { message: 'La calificación máxima es 5' })
  calificacion: number;

  @IsNotEmpty({ message: 'El comentario es obligatorio' })
  @IsString()
  @MinLength(10, { message: 'El comentario debe tener al menos 10 caracteres' })
  @MaxLength(800, { message: 'El comentario no puede exceder 800 caracteres' })
  @Matches(/^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑüÜ\s.,;:¡!¿?'"()\-_/]+$/, {
    message: 'El comentario contiene caracteres no permitidos',
  })
  comentario: string;
}
