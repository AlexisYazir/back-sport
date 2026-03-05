import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('core.orders')
export class Orders {
  @PrimaryGeneratedColumn()
  id_orden: number;

  @Column()
  id_usuario: number;

  @Column()
  id_direccion_envio: number;

  @Column({ length: 100 })
  estado: string;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  subtotal: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  descuento: number;

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  total: number;

  @Column('text')
  metodo_pago: string;

  @Column({ type: 'timestamp' })
  fecha_pago: Date;

  @Column({ type: 'timestamp' })
  fecha_envio: Date;

  @Column({ type: 'timestamp' })
  fecha_entrega: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  fecha_creacion: Date;
}
