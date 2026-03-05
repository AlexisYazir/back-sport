import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('core.roles')
export class Roles {
  @PrimaryGeneratedColumn()
  id_rol: number;

  @Column({ length: 100 })
  rol: string;
}
