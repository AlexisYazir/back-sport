import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('marcas')
export class Marca {
  @PrimaryGeneratedColumn()
  id_marca: number;

  @Column({ length: 100 })
  nombre: string;

  @Column('text')
  imagen: string;
}
