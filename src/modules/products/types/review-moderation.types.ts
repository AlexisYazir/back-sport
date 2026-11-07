import type { Review } from '../entities/reviews/review.entity';

export type ReviewModerationAction = 'conservar' | 'retirar' | 'restaurar';
export type PublicReview = Pick<
  Review,
  | 'id_review'
  | 'id_producto'
  | 'id_usuario'
  | 'calificacion'
  | 'comentario'
  | 'fecha'
>;

export interface AdminReview extends Omit<PublicReview, 'fecha'> {
  fecha: string;
  usuario: string;
  email: string | null;
  producto: string | null;
  retirada: boolean;
  revision: number;
}

export interface ReviewReport {
  id_mensaje: number;
  nombre: string;
  email: string;
  asunto: string | null;
  mensaje: string;
  created_at: string;
  leido: boolean;
  respondido: boolean;
  id_review: number | null;
  id_producto: number | null;
  referencia_valida: boolean;
  estado_atencion: 'pendiente' | 'atendido';
}

export interface ReviewReportPage {
  items: ReviewReport[];
  total: number;
  page: number;
  limit: number;
}

export interface ModerationEvent {
  id_evento: number;
  id_review: number;
  id_mensaje: number | null;
  accion: ReviewModerationAction;
  motivo: string;
  id_administrador: number;
  fecha: string;
  retirada_anterior: boolean;
  retirada_nueva: boolean;
  revision: number;
}

export interface ReviewModerationDetail {
  review: AdminReview;
  reports: ReviewReport[];
  history: ModerationEvent[];
}
