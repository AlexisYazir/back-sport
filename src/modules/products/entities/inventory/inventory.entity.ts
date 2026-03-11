import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('core.inventory')
export class Inventory {
  @PrimaryGeneratedColumn()
  id_inventory: number;

  @Column()
  id_variante: number;

  @Column()
  stock_actual: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  costo_promedio: number;
}
