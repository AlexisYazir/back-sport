import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('faqs')
export class Faq {
  @PrimaryGeneratedColumn()
  id_faq: number;

  @Column({ type: 'text' })
  pregunta: string;

  @Column({ type: 'text' })
  respuesta: string;

  @Column({ default: 0 })
  orden: number;

  @Column({ length: 50, nullable: true })
  seccion: string;

  @Column({ type: 'text', array: true, default: '{}' })
  palabras_clave: string[];

  @Column({ default: true })
  activo: boolean;

  @Column({ default: false })
  destacado: boolean;

  @Column({ default: 0 })
  contador_vistas: number;

  @Column({ default: 0 })
  contador_util: number;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;
}
