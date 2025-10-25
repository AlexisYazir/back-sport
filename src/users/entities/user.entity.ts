import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn()
  id_usuario: number;

  @Column({ length: 30 })
  nombre: string;

  @Column({ length: 40 })
  aPaterno: string;

  @Column({ length: 40 })
  aMaterno: string;

  @Column({ length: 100, nullable: true })
  email: string;

  @Column({ length: 15, nullable: true })
  telefono: string;

  @Column({ length: 255 })
  passw: string;

  @Column({ type: 'int', nullable: true })
  rol: number;

  @Column({ type: 'int', nullable: true })
  activo: number;

  @Column({ length: 255, nullable: true })
  token_verificacion: string;

  @Column({ type: 'datetime', nullable: true })
  token_expiracion: Date;

  @Column({ type: 'timestamp', nullable: true })
  fecha_creacion: Date;

  @Column({ type: 'timestamp', nullable: true })
  fecha_actualizacion: Date;

  @Column({ type: 'tinyint', nullable: true })
  email_verified: number;

  @Column({ type: 'tinyint', nullable: true })
  telefono_verified: number;

  @Column({ length: 255, nullable: true })
  google_id: string;

  @Column({ type: 'int', nullable: true })
  ubicacion: number;
}
