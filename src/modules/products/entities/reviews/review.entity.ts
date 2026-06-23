import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';

@Index(['id_producto', 'id_usuario'], { unique: true })
@Entity('core.reviews')
export class Review {
  @PrimaryGeneratedColumn()
  id_review: number;

  @Column()
  id_producto: number;

  @Column()
  id_usuario: number;

  @Column({ type: 'int' })
  calificacion: number;

  @Column({ type: 'text' })
  comentario: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  fecha: Date;
}
