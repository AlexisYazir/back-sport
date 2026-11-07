import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';
import type { ReviewModerationAction } from '../../types/review-moderation.types';

@Index(['id_review', 'revision'], { unique: true })
@Entity({ schema: 'core', name: 'review_moderation_events' })
export class ReviewModerationEvent {
  @PrimaryGeneratedColumn()
  id_evento: number;

  @Column({ type: 'int' })
  id_review: number;

  @Column({ type: 'int', nullable: true })
  id_mensaje: number | null;

  @Column({ type: 'varchar', length: 16 })
  accion: ReviewModerationAction;

  @Column({ type: 'text' })
  motivo: string;

  @Column({ type: 'int' })
  id_administrador: number;

  @Column({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  fecha: Date;

  @Column({ type: 'boolean' })
  retirada_anterior: boolean;

  @Column({ type: 'boolean' })
  retirada_nueva: boolean;

  @Column({ type: 'int' })
  revision: number;
}
