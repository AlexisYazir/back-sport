import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('core.inventory_movements')
export class InventoryMovements {
  @PrimaryGeneratedColumn()
  id_movimiento: number;

  @Column()
  id_variante: number;

  @Column({ length: 100 })
  tipo: string;

  @Column()
  cantidad: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  costo_unitario: number;

  @Column({ length: 100 })
  referencia_tipo: string;

  @Column()
  referencia_id: number;

  @Column({ type: 'timestamptz', default: () => 'now()' })
  fecha: Date;
}
