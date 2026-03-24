import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('core.deportes')
export class Sports {
  @PrimaryGeneratedColumn()
  id_deporte: number;

  @Column({ length: 100 })
  nombre: string;
}
