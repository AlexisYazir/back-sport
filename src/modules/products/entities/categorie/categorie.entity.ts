import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('core.categories')
export class Category {
  @PrimaryGeneratedColumn()
  id_categoria: number;

  @Column({ length: 100 })
  nombre: string;

  @Column({ type: 'int', nullable: true }) // ← Especificar tipo explícitamente
  id_padre: number | null;
}
