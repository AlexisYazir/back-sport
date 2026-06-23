import { IsIn, IsNotEmpty, IsString } from 'class-validator';

export class UpdateOrderStatusDto {
  @IsNotEmpty({ message: 'El estado es obligatorio' })
  @IsString()
  @IsIn(['pendiente', 'en proceso', 'entregado'], {
    message: 'El estado debe ser pendiente, en proceso o entregado',
  })
  estado: 'pendiente' | 'en proceso' | 'entregado';
}
