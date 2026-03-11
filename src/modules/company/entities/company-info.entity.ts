import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('company_info')
export class CompanyInfo {
  @PrimaryGeneratedColumn()
  id_empresa: number;

  @Column({ length: 100 })
  nombre: string;

  @Column({ length: 13, nullable: true })
  rfc: string;

  @Column({ length: 15, nullable: true })
  telefono: string;

  @Column({ length: 100, nullable: true })
  email: string;

  @Column({ length: 255, nullable: true })
  sitio_web: string;

  @Column({ nullable: true })
  id_direccion: number;

  @Column({ length: 255, nullable: true })
  facebook: string;

  @Column({ length: 255, nullable: true })
  instagram: string;

  @Column({ length: 255, nullable: true })
  twitter: string;

  @Column({ length: 255, nullable: true })
  tiktok: string;

  @Column({ length: 255, nullable: true })
  youtube: string;

  @Column({ length: 100, nullable: true })
  regimen_fiscal: string;

  @Column({ length: 500, nullable: true })
  logo_url: string;

  @Column({ type: 'text', nullable: true })
  horario_atencion: string;

  @Column({ type: 'text', nullable: true })
  mision: string;

  @Column({ type: 'text', nullable: true })
  vision: string;

  @Column({ type: 'text', array: true, default: '{}' })
  valores: string[];

  @Column({ type: 'text', nullable: true })
  mapa_ubicacion: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;
}
