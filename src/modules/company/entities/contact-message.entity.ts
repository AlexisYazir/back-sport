import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('contact_messages')
export class ContactMessage {
  @PrimaryGeneratedColumn()
  id_mensaje: number;

  @Column({ length: 100 })
  nombre: string;

  @Column({ length: 100 })
  email: string;

  @Column({ length: 15, nullable: true })
  telefono: string;

  @Column({ length: 200, nullable: true })
  asunto: string;

  @Column({ type: 'text' })
  mensaje: string;

  @Column({ default: false })
  leido: boolean;

  @Column({ default: false })
  respondido: boolean;

  @Column({ type: 'timestamp', nullable: true })
  fecha_lectura: Date;

  @Column({ nullable: true })
  id_usuario_responde: number;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;
}
