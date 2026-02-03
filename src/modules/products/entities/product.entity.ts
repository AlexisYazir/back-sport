import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('products')
export class Product {
  @PrimaryGeneratedColumn()
  id_producto: number;

  @Column({ length: 100 })
  nombre: string;

  @Column('text')
  descripcion: string;

  @Column()
  categoria: number;

  @Column()
  marca: number;

  @Column({ type: 'json' })
  imagenes: string[];

  @Column({ type: 'decimal', precision: 10, scale: 2, default: 0 })
  precio: number;

  @Column({ type: 'int', nullable: true })
  activo: number;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  fecha_creacion: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  fecha_actualizacion: Date;
}
