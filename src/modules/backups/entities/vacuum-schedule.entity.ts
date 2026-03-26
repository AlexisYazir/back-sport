import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity('core.vacuum_schedules')
export class VacuumScheduleEntity {
  @PrimaryGeneratedColumn()
  id_vacuum_schedule: number;

  @Column({ type: 'varchar', length: 120, unique: true })
  nombre: string;

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

  @Column({ type: 'varchar', length: 100, default: 'core' })
  esquema_objetivo: string;

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
