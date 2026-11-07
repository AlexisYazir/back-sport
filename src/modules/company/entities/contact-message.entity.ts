import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity({ schema: 'core', name: 'contact_messages' })
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
  fecha_lectura: Date | null;

  @Column({ type: 'int', nullable: true })
  id_usuario_responde: number | null;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;
}
