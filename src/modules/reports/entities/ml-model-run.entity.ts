import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { MlPipeline } from './ml-training-schedule.entity';

export type MlRunStatus =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'skipped';

@Entity('core.ml_model_runs')
export class MlModelRunEntity {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id_ejecucion: string;

  @Column({ type: 'integer', nullable: true })
  id_programacion: number | null;

  @Column({ type: 'varchar', length: 20 })
  origen: 'manual' | 'scheduled';

  @Column({ type: 'varchar', length: 20 })
  estado: MlRunStatus;

  @Column({ type: 'jsonb' })
  pipelines: MlPipeline[];

  @Column({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  fecha_inicio: Date;

  @Column({ type: 'timestamptz', nullable: true })
  fecha_fin: Date | null;

  @Column({ type: 'integer', nullable: true })
  duracion_ms: number | null;

  @Column({ type: 'jsonb', nullable: true })
  filas_dataset: Record<string, number> | null;

  @Column({ type: 'jsonb', nullable: true })
  metricas: Record<string, unknown> | null;

  @Column({ type: 'jsonb', nullable: true })
  artefactos: Record<string, unknown> | null;

  @Column({ type: 'text', nullable: true })
  salida: string | null;

  @Column({ type: 'text', nullable: true })
  error: string | null;

  @Column({ type: 'integer', nullable: true })
  ejecutado_por: number | null;

  @Column({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  fecha_creacion: Date;
}
