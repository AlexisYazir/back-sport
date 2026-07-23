import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

export type MlPipeline = 'demand' | 'recommendation' | 'clustering';

@Entity('core.ml_training_schedules')
export class MlTrainingScheduleEntity {
  @PrimaryGeneratedColumn()
  id_programacion: number;

  @Column({ type: 'varchar', length: 120, unique: true })
  nombre: string;

  @Column({ type: 'smallint', default: 1 })
  dia_mes: number;

  @Column({ type: 'time', default: '03:00:00' })
  hora: string;

  @Column({ type: 'varchar', length: 80, default: 'America/Mexico_City' })
  zona_horaria: string;

  @Column({ type: 'jsonb' })
  pipelines: MlPipeline[];

  @Column({ type: 'boolean', default: true })
  activo: boolean;

  @Column({ type: 'timestamptz', nullable: true })
  ultima_ejecucion: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  proxima_ejecucion: Date | null;

  @Column({ type: 'integer', nullable: true })
  creado_por: number | null;

  @Column({ type: 'integer', nullable: true })
  actualizado_por: number | null;

  @Column({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  fecha_creacion: Date;

  @Column({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  fecha_actualizacion: Date;
}
