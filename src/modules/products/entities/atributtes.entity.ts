import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('attributes')
export class Attribute {
  @PrimaryGeneratedColumn()
  id_atributo: number;

  @Column({ length: 100 })
  nombre: string;
}
