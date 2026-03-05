import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';

@Index(['sku'], { unique: true })
@Entity('core.product_variants')
export class ProductVariant {
  @PrimaryGeneratedColumn()
  id_variante: number;

  @Column()
  id_producto: number;

  @Column({ length: 100 })
  sku: string;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  precio: number;

  @Column({ type: 'int', nullable: true })
  stock: number;

  @Column({ type: 'jsonb', default: () => "'[]'" })
  imagenes: string[];
}
