import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { plainToInstance } from 'class-transformer';
import { validateSync } from 'class-validator';
import { DataSource, EntityManager } from 'typeorm';
import {
  ModerateReviewDto,
  ReviewReportsQueryDto,
} from '../dto/reviews/moderation.dto';
import type {
  AdminReview,
  ModerationEvent,
  ReviewModerationDetail,
  ReviewReport,
  ReviewReportPage,
} from '../types/review-moderation.types';

// Coincide con el contrato público que ya envía la app; no interpreta SQL ni enlaces.
export const REVIEW_REPORT_SUBJECT =
  '^Reporte de reseña #([1-9][0-9]{0,14}) · producto #([1-9][0-9]{0,14})$';

export function parseReviewReportSubject(subject: string | null): {
  reviewId: number;
  productId: number;
} | null {
  const match = subject?.match(new RegExp(REVIEW_REPORT_SUBJECT));
  if (!match) return null;
  const reviewId = Number(match[1]),
    productId = Number(match[2]);
  if (reviewId > 2147483647 || productId > 2147483647) return null;
  return { reviewId, productId };
}

type ReportRow = {
  id_mensaje: number;
  nombre: string;
  email: string;
  asunto: string | null;
  mensaje: string;
  created_at: Date | string;
  leido: boolean;
  respondido: boolean;
  referencia_valida: boolean;
  atendido: boolean;
};
type AdminReviewRow = Omit<AdminReview, 'fecha'> & { fecha: Date | string };
type EventRow = Omit<ModerationEvent, 'fecha'> & { fecha: Date | string };
type LockedReview = Pick<
  AdminReview,
  'id_review' | 'id_producto' | 'retirada' | 'revision'
>;

const reportColumns = `m.id_mensaje,m.nombre,m.email,m.asunto,m.mensaje,
  m.created_at,m.leido,m.respondido,
  (r.id_review IS NOT NULL) AS referencia_valida,
  EXISTS(SELECT 1 FROM core.review_moderation_events e WHERE e.id_mensaje=m.id_mensaje) AS atendido`;
const reportJoin = `FROM public.contact_messages m
  LEFT JOIN LATERAL regexp_match(m.asunto,$1) AS ref(parts) ON true
  LEFT JOIN core.reviews r ON r.id_review::text=ref.parts[1]
    AND r.id_producto::text=ref.parts[2]`;

const iso = (value: Date | string): string => new Date(value).toISOString();
function reportResult(row: ReportRow): ReviewReport {
  const reference = parseReviewReportSubject(row.asunto);
  return {
    id_mensaje: row.id_mensaje,
    nombre: row.nombre,
    email: row.email,
    asunto: row.asunto,
    mensaje: row.mensaje,
    created_at: iso(row.created_at),
    leido: row.leido,
    respondido: row.respondido,
    id_review: reference?.reviewId ?? null,
    id_producto: reference?.productId ?? null,
    referencia_valida: row.referencia_valida && reference !== null,
    estado_atencion: row.atendido ? 'atendido' : 'pendiente',
  };
}
function positiveId(id: number): void {
  if (!Number.isSafeInteger(id) || id <= 0 || id > 2147483647)
    throw new BadRequestException('Identificador inválido.');
}

@Injectable()
export class ProductReviewModerationService {
  constructor(
    @InjectDataSource('editorConnection')
    private readonly dataSource: DataSource,
  ) {}

  async getReviewReports(
    query: ReviewReportsQueryDto,
  ): Promise<ReviewReportPage> {
    const values = plainToInstance(ReviewReportsQueryDto, query);
    if (
      validateSync(values, { whitelist: true, forbidNonWhitelisted: true })
        .length
    )
      throw new BadRequestException('Revisa los filtros de reportes.');
    const { estado, page, limit } = values;
    return this.dataSource.transaction('REPEATABLE READ', async (manager) => {
      const where = `WHERE m.asunto LIKE 'Reporte de reseña %'
      AND ($2='todos' OR EXISTS(SELECT 1 FROM core.review_moderation_events e
        WHERE e.id_mensaje=m.id_mensaje)=($2='atendido'))`;
      const counts = await manager.query<{ total: number }[]>(
        `SELECT count(*)::int AS total ${reportJoin} ${where}`,
        [REVIEW_REPORT_SUBJECT, estado],
      );
      const rows = await manager.query<ReportRow[]>(
        `SELECT ${reportColumns} ${reportJoin} ${where}
       ORDER BY m.created_at DESC,m.id_mensaje DESC LIMIT $3 OFFSET $4`,
        [REVIEW_REPORT_SUBJECT, estado, limit, (page - 1) * limit],
      );
      return {
        items: rows.map(reportResult),
        total: counts[0].total,
        page,
        limit,
      };
    });
  }

  async getReviewModeration(id: number): Promise<ReviewModerationDetail> {
    positiveId(id);
    return this.dataSource.transaction('REPEATABLE READ', async (manager) => {
      const rows = await manager.query<AdminReviewRow[]>(
        `SELECT r.id_review,r.id_producto,r.id_usuario,r.calificacion,r.comentario,
       r.fecha,r.retirada,r.revision,
       COALESCE(NULLIF(TRIM(u.nombre),''),'Usuario') AS usuario,u.email,p.nombre AS producto
       FROM core.reviews r LEFT JOIN core.users u ON u.id_usuario=r.id_usuario
       LEFT JOIN core.products p ON p.id_producto=r.id_producto WHERE r.id_review=$1`,
        [id],
      );
      const review = rows[0];
      if (!review) throw new NotFoundException('Reseña no encontrada.');
      const reports = await manager.query<ReportRow[]>(
        `SELECT ${reportColumns} ${reportJoin} WHERE m.asunto=$2
       ORDER BY m.created_at DESC,m.id_mensaje DESC`,
        [
          REVIEW_REPORT_SUBJECT,
          `Reporte de reseña #${id} · producto #${review.id_producto}`,
        ],
      );
      const history = await manager.query<EventRow[]>(
        `SELECT id_evento,id_review,id_mensaje,accion,motivo,id_administrador,fecha,
       retirada_anterior,retirada_nueva,revision FROM core.review_moderation_events
       WHERE id_review=$1 ORDER BY revision ASC`,
        [id],
      );
      return {
        review: { ...review, fecha: iso(review.fecha) },
        reports: reports.map(reportResult),
        history: history.map((event) => ({
          ...event,
          fecha: iso(event.fecha),
        })),
      };
    });
  }

  async moderateReview(
    id: number,
    actorId: number,
    dto: ModerateReviewDto,
  ): Promise<ReviewModerationDetail> {
    positiveId(id);
    positiveId(actorId);
    const decision = plainToInstance(ModerateReviewDto, dto);
    if (
      validateSync(decision, { whitelist: true, forbidNonWhitelisted: true })
        .length
    )
      throw new BadRequestException('Revisa la decisión y su motivo.');
    await this.dataSource.transaction(async (manager) => {
      await this.assertActor(manager, actorId);
      const rows = await manager.query<LockedReview[]>(
        'SELECT id_review,id_producto,retirada,revision FROM core.reviews WHERE id_review=$1 FOR UPDATE',
        [id],
      );
      const review = rows[0];
      if (!review) throw new NotFoundException('Reseña no encontrada.');
      if (review.revision !== decision.revision_esperada)
        throw new ConflictException(
          'La reseña cambió. Actualiza antes de decidir.',
        );
      if (decision.id_mensaje !== undefined) {
        const messages = await manager.query<{ asunto: string | null }[]>(
          'SELECT asunto FROM public.contact_messages WHERE id_mensaje=$1 FOR UPDATE',
          [decision.id_mensaje],
        );
        const reference = parseReviewReportSubject(messages[0]?.asunto ?? null);
        if (
          reference?.reviewId !== id ||
          reference.productId !== review.id_producto
        )
          throw new BadRequestException(
            'El reporte no corresponde a esta reseña.',
          );
      }
      const withdrawn =
        decision.accion === 'conservar'
          ? review.retirada
          : decision.accion === 'retirar';
      const revision = review.revision + 1;
      await manager.query(
        'UPDATE core.reviews SET retirada=$1,revision=$2 WHERE id_review=$3',
        [withdrawn, revision, id],
      );
      await manager.query(
        `INSERT INTO core.review_moderation_events
         (id_review,id_mensaje,accion,motivo,id_administrador,retirada_anterior,retirada_nueva,revision)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          id,
          decision.id_mensaje ?? null,
          decision.accion,
          decision.motivo,
          actorId,
          review.retirada,
          withdrawn,
          revision,
        ],
      );
      if (decision.id_mensaje !== undefined)
        await manager.query(
          `UPDATE public.contact_messages SET leido=true,
           fecha_lectura=COALESCE(fecha_lectura,CURRENT_TIMESTAMP) WHERE id_mensaje=$1`,
          [decision.id_mensaje],
        );
    });
    return this.getReviewModeration(id);
  }

  private async assertActor(
    manager: EntityManager,
    actorId: number,
  ): Promise<void> {
    const actors = await manager.query<{ id_usuario: number }[]>(
      'SELECT id_usuario FROM core.users WHERE id_usuario=$1 AND rol=3 AND activo=1 FOR SHARE',
      [actorId],
    );
    if (!actors.length)
      throw new ForbiddenException(
        'Se requiere una cuenta administradora activa.',
      );
  }
}
