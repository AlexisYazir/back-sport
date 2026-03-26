import { Entity, PrimaryColumn } from 'typeorm';

@Entity('core.product_deportes')
export class ProductSport {
  @PrimaryColumn()
  id_producto: number;

  @PrimaryColumn()
  id_deporte: number;
}
