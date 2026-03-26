import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity('core.backup_retention_policies')
export class BackupRetentionPolicyEntity {
  @PrimaryGeneratedColumn()
  id_retention_policy: number;

  @Column({ type: 'varchar', length: 120, unique: true })
  nombre: string;

  @Column({ type: 'varchar', length: 20, nullable: true })
  tipo_backup: 'full' | 'critical' | null;

  @Column({ type: 'varchar', length: 150, default: 'backups' })
  carpeta_base: string;

  @Column({ type: 'int', default: 7 })
  retencion_dias: number;

  @Column({ type: 'varchar', length: 20 })
  modo_programacion: 'cron' | 'weekly' | 'datetime';

  @Column({ type: 'varchar', length: 100, nullable: true })
  cron_expression: string | null;

  @Column({ type: 'smallint', nullable: true })
  dia_semana: number | null;

  @Column({ type: 'time', nullable: true })
  hora: string | null;

  @Column({ type: 'timestamp', nullable: true })
  fecha_ejecucion: Date | null;

  @Column({ type: 'boolean', default: true })
  activo: boolean;

  @Column({ type: 'timestamp', nullable: true })
  ultima_ejecucion: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  proxima_ejecucion: Date | null;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  creado_en: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  actualizado_en: Date;
}
