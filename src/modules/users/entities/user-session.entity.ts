import { Column, Entity, PrimaryColumn } from 'typeorm';

@Entity('core.user_sessions')
export class UserSession {
  @PrimaryColumn({ type: 'uuid' })
  id_sesion: string;

  @Column({ type: 'int' })
  id_usuario: number;

  @Column({ type: 'varchar', length: 255 })
  refresh_token_hash: string;

  @Column({ type: 'varchar', length: 150, nullable: true })
  device_name: string | null;

  @Column({ type: 'text', nullable: true })
  user_agent: string | null;

  @Column({ type: 'inet', nullable: true })
  ip_address: string | null;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  creada_en: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  ultima_actividad: Date;

  @Column({ type: 'timestamp' })
  expira_en: Date;

  @Column({ type: 'timestamp', nullable: true })
  revocada_en: Date | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  motivo_revocacion: string | null;

  @Column({ type: 'uuid', nullable: true })
  reemplazada_por: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  csrf_token_hash: string | null;
}
