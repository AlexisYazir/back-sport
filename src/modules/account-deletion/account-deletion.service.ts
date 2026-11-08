import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { randomInt, randomUUID, randomBytes } from 'node:crypto';
import { DataSource, EntityManager } from 'typeorm';
import { User } from '../users/entities/user.entity';
import { MailService } from '../../services/mail/mail.service';
import { DELETION_LOCK_NAMESPACE } from './account-deletion-access.service';
import {
  AccountDeletionDataService,
  RetentionPolicy,
} from './account-deletion-data.service';
import { DeletionSecrets } from './deletion-secrets';
import { DeletionRecoveryGate } from './deletion-recovery-gate';
import type {
  DeletionPrincipal,
  DeletionRequest,
  DeletionResult,
} from './deletion.types';
import type {
  DeletionLedger,
  RecordedDeletionIntent,
  DeletionRetention,
} from './ledger/deletion-ledger';

export const DELETION_LEDGER = 'ACCOUNT_DELETION_LEDGER';
const MINUTE = 60_000,
  DAY = 24 * 60 * MINUTE;
const token = (): string => randomBytes(32).toString('base64url');

@Injectable()
export class AccountDeletionService {
  constructor(
    @InjectDataSource('adminConnection') private readonly source: DataSource,
    private readonly config: ConfigService,
    private readonly secrets: DeletionSecrets,
    private readonly data: AccountDeletionDataService,
    private readonly mail: MailService,
    @Inject(DELETION_LEDGER) private readonly ledger: DeletionLedger,
    private readonly gate: DeletionRecoveryGate,
  ) {}

  validateConfiguration(): void {
    if (this.config.get<string>('ACCOUNT_DELETION_ENABLED') !== 'true') return;
    this.secrets.hash('configuration', 'startup', 'validate');
    const basis = this.config.get<string>('ACCOUNT_DELETION_RETENTION_BASIS');
    const days = this.config.get<string>('ACCOUNT_DELETION_RETENTION_DAYS');
    if ((basis !== undefined || days !== undefined) && !this.configuredPolicy())
      throw new Error('ACCOUNT_DELETION_RETENTION_CONFIGURATION_INVALID');
  }

  private enabled(): void {
    if (this.config.get<string>('ACCOUNT_DELETION_ENABLED') !== 'true')
      throw new ServiceUnavailableException(
        'La eliminación de cuentas aún no está habilitada',
      );
    try {
      this.gate.assertDeletionReady();
    } catch {
      throw new ServiceUnavailableException(
        'La eliminación de cuentas no está disponible temporalmente',
      );
    }
  }
  private async lock(manager: EntityManager, id: number): Promise<void> {
    await manager.query('SELECT pg_advisory_xact_lock($1,$2)', [
      DELETION_LOCK_NAMESPACE,
      id,
    ]);
  }
  private async principal(
    manager: EntityManager,
    actor: DeletionPrincipal,
  ): Promise<User> {
    const users = await manager
      .getRepository(User)
      .findBy({ id_usuario: actor.id_usuario });
    const accounts = await manager.query<{ state: string }[]>(
      'SELECT state FROM core.account_deletion_accounts WHERE user_id=$1',
      [actor.id_usuario],
    );
    const sessions = await manager.query<{ id_sesion: string }[]>(
      'SELECT id_sesion FROM core.user_sessions WHERE id_sesion=$1 AND id_usuario=$2 AND revocada_en IS NULL AND expira_en>clock_timestamp() FOR UPDATE',
      [actor.sessionId, actor.id_usuario],
    );
    if (
      users.length !== 1 ||
      accounts[0]?.state !== 'active' ||
      sessions.length !== 1
    )
      throw new UnauthorizedException('La sesión ya no está activa');
    return users[0];
  }
  private async load(
    manager: EntityManager,
    id: string,
  ): Promise<DeletionRequest> {
    const rows = await manager.query<DeletionRequest[]>(
      'SELECT * FROM core.account_deletion_requests WHERE request_id=$1 FOR UPDATE',
      [id],
    );
    if (rows.length !== 1)
      throw new NotFoundException('Solicitud no disponible');
    return rows[0];
  }
  private resultOf(row: DeletionRequest): DeletionResult {
    return {
      requestId: row.request_id,
      status: row.status,
      reason: row.reason,
      retainedCategories: row.retained_categories,
      notification: row.notification_status,
      ...(row.retain_until && row.retention_basis
        ? {
            retention: {
              until: new Date(row.retain_until).toISOString(),
              basis: row.retention_basis,
              identifiersExpired: !!row.identifiers_expired_at,
            },
          }
        : {}),
    };
  }
  private identity(user: User): string {
    return this.secrets.hash(
      'legacy',
      String(user.id_usuario),
      new Date(user.fecha_creacion).toISOString(),
    );
  }
  private async identityEmail(
    manager: EntityManager,
    userId: number,
  ): Promise<string> {
    const rows = await manager.query<{ identity_email: string | null }[]>(
      'SELECT identity_email FROM core.account_deletion_accounts WHERE user_id=$1',
      [userId],
    );
    if (!rows[0]?.identity_email)
      throw new BadRequestException(
        'Verifica la identidad de tu cuenta antes de solicitar la eliminación',
      );
    return rows[0].identity_email;
  }

  async request(actor: DeletionPrincipal): Promise<{
    requestId: string;
    receiptToken: string;
    status: 'received';
    expiresAt: string;
  }> {
    this.enabled();
    const requestId = randomUUID(),
      receiptToken = token(),
      code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    const expiresAt = new Date(Date.now() + 10 * MINUTE);
    const email = await this.source.transaction(async (manager) => {
      await this.lock(manager, actor.id_usuario);
      const user = await this.principal(manager, actor);
      if (user.rol !== 1)
        throw new ConflictException(
          'Las cuentas con permisos de administración requieren atención específica',
        );
      const identityEmail = await this.identityEmail(manager, user.id_usuario);
      const recent = await manager.query<{ requested_at: Date }[]>(
        "SELECT requested_at FROM core.account_deletion_requests WHERE user_id=$1 AND requested_at>clock_timestamp()-interval '1 hour' ORDER BY requested_at DESC",
        [user.id_usuario],
      );
      if (
        recent.length >= 5 ||
        (recent[0] &&
          Date.now() - new Date(recent[0].requested_at).getTime() < MINUTE)
      )
        throw new ConflictException('Espera antes de solicitar otro código');
      await manager.query(
        "UPDATE core.account_deletion_requests SET status='error',reason='replaced',code_hash=NULL,authorization_hash=NULL,updated_at=clock_timestamp() WHERE user_id=$1 AND status IN ('received','identity_verified')",
        [user.id_usuario],
      );
      await manager.query(
        `INSERT INTO core.account_deletion_requests(request_id,user_id,account_id,session_id,status,email_hash,code_hash,code_expires_at,receipt_hash,receipt_expires_at)
        SELECT $1,a.user_id,a.account_id,$2,'received',$3,$4,$5,$6,$7 FROM core.account_deletion_accounts a WHERE a.user_id=$8 AND a.state='active'`,
        [
          requestId,
          actor.sessionId,
          this.secrets.hash('email', requestId, identityEmail.toLowerCase()),
          this.secrets.hash('code', requestId, code),
          expiresAt,
          this.secrets.hash('receipt', requestId, receiptToken),
          new Date(Date.now() + 7 * DAY),
          user.id_usuario,
        ],
      );
      return identityEmail;
    });
    try {
      await this.mail.sendAccountDeletionCode(email, code);
    } catch {
      await this.source.query(
        "UPDATE core.account_deletion_requests SET status='error',reason='code_delivery_failed',code_hash=NULL WHERE request_id=$1 AND status='received'",
        [requestId],
      );
      throw new ServiceUnavailableException(
        'No pudimos enviar el código. Intenta nuevamente más tarde',
      );
    }
    return {
      requestId,
      receiptToken,
      status: 'received',
      expiresAt: expiresAt.toISOString(),
    };
  }

  async verify(
    actor: DeletionPrincipal,
    requestId: string,
    code: string,
  ): Promise<{
    status: 'identity_verified';
    confirmationToken: string;
    expiresAt: string;
    consequences: {
      irreversible: true;
      endsAllSessions: true;
      newRegistrationIsSeparate: true;
      retainedCategories: string[];
      requiresAttention: boolean;
      reason: string | null;
      retentionPolicy: RetentionPolicy | null;
    };
  }> {
    this.enabled();
    const confirmationToken = token(),
      expiresAt = new Date(Date.now() + 5 * MINUTE);
    const error = await this.source.transaction(async (manager) => {
      await this.lock(manager, actor.id_usuario);
      const user = await this.principal(manager, actor),
        row = await this.load(manager, requestId);
      if (
        row.user_id !== actor.id_usuario ||
        row.session_id !== actor.sessionId
      )
        throw new NotFoundException('Solicitud no disponible');
      if (row.status !== 'received')
        return new ConflictException('Solicita un código nuevo');
      const expired =
        !row.code_expires_at ||
        new Date(row.code_expires_at).getTime() <= Date.now();
      const identityEmail = await this.identityEmail(manager, user.id_usuario);
      const changed = !this.secrets.matches(
        'email',
        requestId,
        identityEmail.toLowerCase(),
        row.email_hash,
      );
      if (expired || changed || row.attempts >= 5) {
        await manager.query(
          "UPDATE core.account_deletion_requests SET status='error',reason=$2,code_hash=NULL,updated_at=clock_timestamp() WHERE request_id=$1",
          [requestId, changed ? 'identity_changed' : 'code_expired'],
        );
        return new BadRequestException(
          'El código ya no es válido. Solicita uno nuevo',
        );
      }
      if (
        !/^\d{6}$/.test(code) ||
        !this.secrets.matches('code', requestId, code, row.code_hash)
      ) {
        await manager.query(
          `UPDATE core.account_deletion_requests SET attempts=attempts+1,
          status=CASE WHEN attempts+1>=5 THEN 'error' ELSE status END,
          reason=CASE WHEN attempts+1>=5 THEN 'attempts_exhausted' ELSE reason END,
          code_hash=CASE WHEN attempts+1>=5 THEN NULL ELSE code_hash END,updated_at=clock_timestamp() WHERE request_id=$1`,
          [requestId],
        );
        return new BadRequestException('Código incorrecto o no disponible');
      }
      await manager.query(
        "UPDATE core.account_deletion_requests SET status='identity_verified',code_hash=NULL,authorization_hash=$2,authorization_expires_at=$3,updated_at=clock_timestamp() WHERE request_id=$1",
        [
          requestId,
          this.secrets.hash('authorization', requestId, confirmationToken),
          expiresAt,
        ],
      );
      return null;
    });
    if (error) throw error;
    let impact: { reason: string | null; categories: string[] };
    try {
      impact = await this.source.transaction(async (manager) => {
        const user = await this.principal(manager, actor);
        const assessment = await this.data.assess(manager, user);
        return {
          reason:
            assessment.reason ??
            (assessment.categories.length && !this.configuredPolicy()
              ? 'retention_policy_required'
              : null),
          categories: assessment.categories,
        };
      });
    } catch {
      impact = { reason: 'schema_review_required', categories: [] };
    }
    return {
      status: 'identity_verified',
      confirmationToken,
      expiresAt: expiresAt.toISOString(),
      consequences: {
        irreversible: true,
        endsAllSessions: true,
        newRegistrationIsSeparate: true,
        retainedCategories: impact.categories,
        requiresAttention: !!impact.reason,
        reason: impact.reason,
        retentionPolicy: this.configuredPolicy() ?? null,
      },
    };
  }

  async confirm(
    actor: DeletionPrincipal,
    requestId: string,
    confirmationToken: string,
    confirmed: boolean,
  ): Promise<DeletionResult> {
    this.enabled();
    if (confirmed !== true)
      throw new BadRequestException(
        'Debes confirmar expresamente la eliminación',
      );
    let ledgerAttempted = false;
    try {
      await this.source.transaction(async (manager) => {
        await this.lock(manager, actor.id_usuario);
        const user = await this.principal(manager, actor),
          row = await this.load(manager, requestId);
        if (user.rol !== 1)
          throw new ConflictException(
            'Las cuentas con permisos de administración requieren atención específica',
          );
        const identityEmail = await this.identityEmail(
          manager,
          user.id_usuario,
        );
        if (
          row.user_id !== actor.id_usuario ||
          row.session_id !== actor.sessionId
        )
          throw new NotFoundException('Solicitud no disponible');
        if (
          row.status !== 'identity_verified' ||
          !row.authorization_expires_at ||
          new Date(row.authorization_expires_at).getTime() <= Date.now() ||
          !this.secrets.matches(
            'authorization',
            requestId,
            confirmationToken,
            row.authorization_hash,
          ) ||
          !this.secrets.matches(
            'email',
            requestId,
            identityEmail.toLowerCase(),
            row.email_hash,
          )
        )
          throw new BadRequestException('La confirmación ya no es válida');
        // The independent intent is durable BEFORE acknowledging an irreversible confirmation.
        ledgerAttempted = true;
        await this.ledger.recordIntent({
          operationId: requestId,
          accountId: row.account_id,
          legacyUserId: user.id_usuario,
          legacyFingerprint: this.identity(user),
        });
        await manager.query(
          "UPDATE core.account_deletion_requests SET status='deletion_confirmed',code_hash=NULL,authorization_hash=NULL,updated_at=clock_timestamp() WHERE request_id=$1",
          [requestId],
        );
        await manager.query(
          "SELECT set_config('sportcenter.account_deletion',$1,true)",
          [requestId],
        );
        await manager.query(
          "UPDATE core.account_deletion_accounts SET state='deleting',confirmed_at=clock_timestamp() WHERE user_id=$1",
          [user.id_usuario],
        );
        await manager.query(
          "UPDATE core.user_sessions SET revocada_en=clock_timestamp(),motivo_revocacion='account_deletion',refresh_token_hash='!revoked',csrf_token_hash=NULL WHERE id_usuario=$1",
          [user.id_usuario],
        );
        await manager.query(
          `INSERT INTO core.account_deletion_notifications(request_id,encrypted_recipient,expires_at)
        VALUES($1,$2,$3) ON CONFLICT(request_id) DO NOTHING`,
          [
            requestId,
            this.secrets.encrypt(identityEmail),
            new Date(Date.now() + DAY),
          ],
        );
      });
    } catch (error) {
      if (!ledgerAttempted) throw error;
      this.gate.invalidate();
      try {
        await this.gate.reconcileBeforeServing((intent) => this.replay(intent));
        const recovered = await this.source.query<DeletionRequest[]>(
          'SELECT * FROM core.account_deletion_requests WHERE request_id=$1',
          [requestId],
        );
        if (
          recovered[0] &&
          ['completed', 'requires_attention'].includes(recovered[0].status)
        )
          return this.resultOf(recovered[0]);
      } catch {
        /* Keep ordinary traffic closed until the durable outcome is verified. */
      }
      throw new ServiceUnavailableException(
        'No pudimos comprobar el resultado. Conserva el comprobante y consulta antes de reintentar',
      );
    }
    return this.process(requestId);
  }

  private configuredPolicy(): RetentionPolicy | undefined {
    const basis = this.config
      .get<string>('ACCOUNT_DELETION_RETENTION_BASIS')
      ?.trim();
    const days = Number(
      this.config.get<string>('ACCOUNT_DELETION_RETENTION_DAYS'),
    );
    return basis && Number.isSafeInteger(days) && days > 0 && days <= 36500
      ? { basis, days }
      : undefined;
  }

  private async durableRetention(
    requestId: string,
    categories: string[],
    policy?: RetentionPolicy,
  ): Promise<Readonly<DeletionRetention> | undefined> {
    const snapshot = await this.ledger.verifyAndRead();
    const intent = snapshot.intents.find(
      (item) => item.operationId === requestId,
    );
    if (!intent) throw new Error('ACCOUNT_DELETION_INTENT_REQUIRED');
    if (
      categories.some(
        (category) => !['orders', 'payments', 'returns'].includes(category),
      )
    )
      throw new Error('ACCOUNT_DELETION_SCHEMA_REVIEW_REQUIRED');
    if (intent.retention) {
      if (
        categories.some(
          (category) =>
            !intent.retention!.categories.includes(
              category as 'orders' | 'payments' | 'returns',
            ),
        )
      )
        throw new Error('ACCOUNT_DELETION_SCHEMA_REVIEW_REQUIRED');
      if (
        policy &&
        intent.retention.basisHash !==
          this.secrets.hash('retention', requestId, policy.basis.trim())
      )
        throw new ConflictException(
          'La conservación ya fue fijada y no puede ampliarse',
        );
      return intent.retention;
    }
    if (!categories.length) return undefined;
    if (!policy || intent.completed)
      throw new Error('ACCOUNT_DELETION_RETENTION_RECOVERY_REQUIRED');
    const retention: DeletionRetention = {
      until: new Date(Date.now() + policy.days * DAY).toISOString(),
      basisHash: this.secrets.hash('retention', requestId, policy.basis.trim()),
      categories: categories as ('orders' | 'payments' | 'returns')[],
    };
    try {
      await this.ledger.recordRetention(requestId, retention);
    } catch (error) {
      this.gate.invalidate();
      throw error;
    }
    return retention;
  }

  async process(
    requestId: string,
    policy?: RetentionPolicy,
  ): Promise<DeletionResult> {
    this.enabled();
    if (
      policy &&
      (!policy.basis.trim() ||
        !Number.isSafeInteger(policy.days) ||
        policy.days < 1 ||
        policy.days > 36500)
    )
      throw new BadRequestException('La regla de conservación no es válida');
    await this.source.query(
      "UPDATE core.account_deletion_requests SET status='in_progress',updated_at=clock_timestamp() WHERE request_id=$1 AND status='deletion_confirmed'",
      [requestId],
    );
    try {
      await this.source.transaction(async (manager) => {
        const initial = await manager.query<{ user_id: number }[]>(
          'SELECT user_id FROM core.account_deletion_requests WHERE request_id=$1',
          [requestId],
        );
        if (!initial[0]) throw new NotFoundException('Solicitud no disponible');
        await this.lock(manager, initial[0].user_id);
        const row = await this.load(manager, requestId);
        if (row.status === 'completed') return;
        if (
          ![
            'deletion_confirmed',
            'in_progress',
            'requires_attention',
            'error',
          ].includes(row.status)
        )
          throw new ConflictException(
            'La eliminación todavía no fue confirmada',
          );
        const accounts = await manager.query<{ state: string }[]>(
          'SELECT state FROM core.account_deletion_accounts WHERE user_id=$1',
          [row.user_id],
        );
        if (accounts[0]?.state === 'active')
          throw new ConflictException(
            'La eliminación todavía no fue confirmada',
          );
        const user = await manager
          .getRepository(User)
          .findOneByOrFail({ id_usuario: row.user_id });
        const assessment = await this.data.assess(manager, user);
        const retention = policy ?? this.configuredPolicy();
        const reason =
          assessment.reason ??
          (assessment.categories.length && !retention
            ? 'retention_policy_required'
            : null);
        if (reason) {
          await manager.query(
            "UPDATE core.account_deletion_requests SET status='requires_attention',reason=$2,retained_categories=$3::jsonb,updated_at=clock_timestamp() WHERE request_id=$1",
            [requestId, reason, JSON.stringify(assessment.categories)],
          );
          await this.data.minimizePending(
            manager,
            user,
            requestId,
            assessment.columns,
          );
          return;
        }
        await manager.query(
          "UPDATE core.account_deletion_requests SET status='in_progress',reason=NULL,updated_at=clock_timestamp() WHERE request_id=$1",
          [requestId],
        );
        const durable = await this.durableRetention(
          requestId,
          assessment.categories,
          retention,
        );
        const notify = await this.identityEmail(manager, user.id_usuario);
        await manager.query(
          `INSERT INTO core.account_deletion_notifications(request_id,encrypted_recipient,expires_at)
          VALUES($1,$2,$3) ON CONFLICT(request_id) DO UPDATE SET encrypted_recipient=EXCLUDED.encrypted_recipient,
          expires_at=EXCLUDED.expires_at,attempts=0 WHERE core.account_deletion_notifications.sent_at IS NULL`,
          [requestId, this.secrets.encrypt(notify), new Date(Date.now() + DAY)],
        );
        if (durable && retention)
          await manager.query(
            `INSERT INTO core.account_deletion_retention(request_id,basis,retain_until,categories)
          VALUES($1,$2,$3,$4::jsonb)
          ON CONFLICT(request_id) DO NOTHING`,
            [
              requestId,
              retention.basis,
              durable.until,
              JSON.stringify(durable.categories),
            ],
          );
        await this.data.purge(manager, user, requestId, assessment.columns);
        await manager.query(
          `UPDATE core.account_deletion_requests SET email_hash=NULL,code_hash=NULL,authorization_hash=NULL,
          receipt_hash=CASE WHEN request_id=$2 THEN receipt_hash ELSE '!revoked' END,
          receipt_expires_at=CASE WHEN request_id=$2 THEN receipt_expires_at ELSE clock_timestamp() END WHERE user_id=$1`,
          [row.user_id, requestId],
        );
        await manager.query(
          "UPDATE core.account_deletion_accounts SET state='deleted',identity_email=NULL,completed_at=clock_timestamp() WHERE user_id=$1",
          [row.user_id],
        );
        await manager.query(
          `UPDATE core.account_deletion_requests SET status='completed',reason=NULL,email_hash=NULL,
          code_hash=NULL,authorization_hash=NULL,retained_categories=$2::jsonb,
          notification_status=CASE WHEN EXISTS(SELECT 1 FROM core.account_deletion_notifications WHERE request_id=$1 AND encrypted_recipient IS NOT NULL) THEN 'pending' ELSE 'not_required' END,
          receipt_expires_at=clock_timestamp()+interval '7 days',updated_at=clock_timestamp() WHERE request_id=$1`,
          [requestId, JSON.stringify(assessment.categories)],
        );
        if (durable && new Date(durable.until).getTime() <= Date.now()) {
          await this.data.expireRetainedIdentifiers(
            manager,
            row.user_id,
            assessment.columns,
          );
          await manager.query(
            'UPDATE core.account_deletion_retention SET identifiers_expired_at=clock_timestamp() WHERE request_id=$1',
            [requestId],
          );
        }
      });
    } catch (error) {
      if (
        error instanceof NotFoundException ||
        error instanceof ConflictException
      )
        throw error;
      const reason =
        error instanceof Error &&
        error.message === 'ACCOUNT_DELETION_SCHEMA_REVIEW_REQUIRED'
          ? 'schema_review_required'
          : 'processing_failed';
      await this.source.query(
        "UPDATE core.account_deletion_requests SET status=$2,reason=$3,updated_at=clock_timestamp() WHERE request_id=$1 AND status<>'completed'",
        [
          requestId,
          reason === 'schema_review_required' ? 'requires_attention' : 'error',
          reason,
        ],
      );
    }
    const rows = await this.source.query<DeletionRequest[]>(
      'SELECT * FROM core.account_deletion_requests WHERE request_id=$1',
      [requestId],
    );
    if (rows[0]?.status === 'completed') {
      await this.expireRetainedRecords(requestId);
      try {
        await this.ledger.markCompleted(requestId);
      } catch {
        this.gate.invalidate();
        throw new ServiceUnavailableException(
          'La operación quedó registrada; consulta su resultado antes de reintentar',
        );
      }
      await this.deliverNotification(requestId);
    }
    const final = await this.source.query<DeletionRequest[]>(
      'SELECT r.*,a.state AS account_state,t.retain_until,t.basis AS retention_basis,t.identifiers_expired_at FROM core.account_deletion_requests r JOIN core.account_deletion_accounts a ON a.user_id=r.user_id LEFT JOIN core.account_deletion_retention t USING(request_id) WHERE r.request_id=$1',
      [requestId],
    );
    return this.resultOf(final[0]);
  }

  async result(
    requestId: string,
    receiptToken: string,
  ): Promise<DeletionResult> {
    // Receipt-only recovery remains available after revoking all authentication sessions.
    if (this.config.get<string>('ACCOUNT_DELETION_ENABLED') !== 'true')
      throw new NotFoundException();
    try {
      this.gate.assertApplicationReady();
    } catch {
      throw new ServiceUnavailableException(
        'El resultado está pendiente de verificación; conserva el comprobante',
      );
    }
    const rows = await this.source.query<DeletionRequest[]>(
      'SELECT r.*,a.state AS account_state,t.retain_until,t.basis AS retention_basis,t.identifiers_expired_at FROM core.account_deletion_requests r JOIN core.account_deletion_accounts a ON a.user_id=r.user_id LEFT JOIN core.account_deletion_retention t USING(request_id) WHERE r.request_id=$1',
      [requestId],
    );
    const row = rows[0];
    if (
      !row ||
      (new Date(row.receipt_expires_at).getTime() <= Date.now() &&
        !(
          row.account_state === 'deleting' &&
          (['deletion_confirmed', 'in_progress', 'requires_attention'].includes(
            row.status,
          ) ||
            (row.status === 'error' && row.reason === 'processing_failed'))
        )) ||
      !this.secrets.matches(
        'receipt',
        requestId,
        receiptToken,
        row.receipt_hash,
      )
    )
      throw new NotFoundException('Solicitud no disponible');
    return this.resultOf(row);
  }

  async deliverNotification(requestId: string): Promise<void> {
    await this.source.transaction(async (manager) => {
      const rows = await manager.query<
        {
          encrypted_recipient: string | null;
          attempts: number;
          expires_at: Date;
          status: string;
        }[]
      >(
        `SELECT n.*,r.status FROM core.account_deletion_notifications n JOIN core.account_deletion_requests r USING(request_id) WHERE n.request_id=$1 FOR UPDATE OF n`,
        [requestId],
      );
      const row = rows[0];
      if (!row?.encrypted_recipient || row.status !== 'completed') return;
      if (
        new Date(row.expires_at).getTime() <= Date.now() ||
        row.attempts >= 5
      ) {
        await manager.query(
          'UPDATE core.account_deletion_notifications SET encrypted_recipient=NULL WHERE request_id=$1',
          [requestId],
        );
        await manager.query(
          "UPDATE core.account_deletion_requests SET notification_status='unavailable' WHERE request_id=$1",
          [requestId],
        );
        return;
      }
      try {
        await this.mail.sendAccountDeletionResult(
          this.secrets.decrypt(row.encrypted_recipient),
          requestId,
        );
        await manager.query(
          'UPDATE core.account_deletion_notifications SET encrypted_recipient=NULL,sent_at=clock_timestamp(),attempts=attempts+1 WHERE request_id=$1',
          [requestId],
        );
        await manager.query(
          "UPDATE core.account_deletion_requests SET notification_status='sent' WHERE request_id=$1",
          [requestId],
        );
      } catch {
        await manager.query(
          'UPDATE core.account_deletion_notifications SET attempts=attempts+1 WHERE request_id=$1',
          [requestId],
        );
        if (row.attempts + 1 >= 5) {
          await manager.query(
            'UPDATE core.account_deletion_notifications SET encrypted_recipient=NULL WHERE request_id=$1',
            [requestId],
          );
          await manager.query(
            "UPDATE core.account_deletion_requests SET notification_status='unavailable' WHERE request_id=$1",
            [requestId],
          );
        }
      }
    });
  }

  async listPending(): Promise<DeletionResult[]> {
    this.enabled();
    const rows = await this.source.query<DeletionRequest[]>(
      `SELECT r.*,CASE WHEN r.status='completed' THEN 'retention_cleanup_due' ELSE r.reason END AS reason
       FROM core.account_deletion_requests r JOIN core.account_deletion_accounts a ON a.user_id=r.user_id
       LEFT JOIN core.account_deletion_retention t USING(request_id) WHERE a.state<>'active' AND
       (r.status IN ('deletion_confirmed','in_progress','requires_attention','error') OR
       (r.status='completed' AND t.retain_until<=clock_timestamp() AND t.identifiers_expired_at IS NULL))
       ORDER BY r.requested_at LIMIT 100`,
    );
    return rows.map((row) => this.resultOf(row));
  }

  async retryNotifications(): Promise<void> {
    this.enabled();
    const rows = await this.source.query<
      { request_id: string }[]
    >(`SELECT n.request_id FROM core.account_deletion_notifications n JOIN core.account_deletion_requests r USING(request_id)
      WHERE n.encrypted_recipient IS NOT NULL AND r.status='completed' LIMIT 20`);
    for (const row of rows) await this.deliverNotification(row.request_id);
    await this.source.query(
      "UPDATE core.account_deletion_requests r SET notification_status='unavailable' FROM core.account_deletion_notifications n WHERE n.request_id=r.request_id AND n.expires_at<=clock_timestamp() AND n.encrypted_recipient IS NOT NULL AND r.notification_status='pending'",
    );
    await this.source.query(
      'UPDATE core.account_deletion_notifications SET encrypted_recipient=NULL WHERE expires_at<=clock_timestamp()',
    );
  }

  async expireRetainedRecords(requestId?: string): Promise<void> {
    const rows = await this.source.query<
      { user_id: number; request_id: string }[]
    >(
      `SELECT r.user_id,t.request_id FROM core.account_deletion_retention t
      JOIN core.account_deletion_requests r USING(request_id) WHERE r.status='completed'
      AND t.retain_until<=clock_timestamp() AND t.identifiers_expired_at IS NULL
      AND ($1::uuid IS NULL OR t.request_id=$1::uuid) LIMIT 100`,
      [requestId ?? null],
    );
    for (const row of rows)
      await this.source.transaction(async (manager) => {
        await this.lock(manager, row.user_id);
        const columns = await this.data.inventory(manager);
        await this.data.expireRetainedIdentifiers(
          manager,
          row.user_id,
          columns,
        );
        await manager.query(
          'UPDATE core.account_deletion_retention SET identifiers_expired_at=clock_timestamp() WHERE request_id=$1',
          [row.request_id],
        );
      });
  }

  async replay(
    intent: Readonly<RecordedDeletionIntent>,
  ): Promise<'completed' | 'restricted'> {
    return this.source.transaction(async (manager) => {
      await this.lock(manager, intent.legacyUserId);
      // A pre-creation backup must not let its restored sequence reuse a retired ID.
      await manager.query(
        `SELECT setval(pg_get_serial_sequence('core.users','id_usuario'),
        GREATEST(COALESCE(pg_sequence_last_value(pg_get_serial_sequence('core.users','id_usuario')::regclass),0),
        COALESCE((SELECT max(id_usuario) FROM core.users),0),$1::bigint),true)`,
        [intent.legacyUserId],
      );
      const user = await manager
        .getRepository(User)
        .findOneBy({ id_usuario: intent.legacyUserId });
      if (!user) return 'completed';
      const identities = await manager.query<
        { account_id: string; state: string }[]
      >(
        'SELECT account_id,state FROM core.account_deletion_accounts WHERE user_id=$1',
        [user.id_usuario],
      );
      if (!identities[0])
        throw new Error('ACCOUNT_DELETION_RECOVERY_SCHEMA_REQUIRED');
      if (
        identities[0].account_id !== intent.accountId &&
        this.identity(user) !== intent.legacyFingerprint
      )
        throw new Error('ACCOUNT_DELETION_RECOVERY_IDENTITY_MISMATCH');
      const columns = await this.data.inventory(manager);
      await manager.query(
        "UPDATE core.account_deletion_requests SET status='error',reason='restore_replaced',code_hash=NULL,authorization_hash=NULL WHERE user_id=$1 AND request_id<>$2 AND status IN ('received','identity_verified')",
        [user.id_usuario, intent.operationId],
      );
      await manager.query(
        `INSERT INTO core.account_deletion_requests(request_id,user_id,account_id,session_id,status,receipt_hash,receipt_expires_at)
        VALUES($1,$2,$3,$4,'deletion_confirmed',$5,clock_timestamp()) ON CONFLICT(request_id) DO UPDATE
        SET status=CASE WHEN core.account_deletion_requests.status='completed' THEN 'completed' ELSE 'deletion_confirmed' END`,
        [
          intent.operationId,
          user.id_usuario,
          intent.accountId,
          randomUUID(),
          this.secrets.hash('receipt', intent.operationId, token()),
        ],
      );
      await manager.query(
        "SELECT set_config('sportcenter.account_deletion',$1,true)",
        [intent.operationId],
      );
      await manager.query(
        "UPDATE core.account_deletion_accounts SET state=CASE WHEN state='deleted' THEN state ELSE 'deleting' END,confirmed_at=COALESCE(confirmed_at,clock_timestamp()) WHERE user_id=$1",
        [user.id_usuario],
      );
      await manager.query(
        "UPDATE core.user_sessions SET revocada_en=clock_timestamp(),refresh_token_hash='!revoked',csrf_token_hash=NULL WHERE id_usuario=$1",
        [user.id_usuario],
      );
      if (!intent.completed) {
        const anchor = await manager.query<{ identity_email: string | null }[]>(
          'SELECT identity_email FROM core.account_deletion_accounts WHERE user_id=$1',
          [user.id_usuario],
        );
        if (anchor[0]?.identity_email)
          await manager.query(
            'INSERT INTO core.account_deletion_notifications(request_id,encrypted_recipient,expires_at) VALUES($1,$2,$3) ON CONFLICT(request_id) DO NOTHING',
            [
              intent.operationId,
              this.secrets.encrypt(anchor[0].identity_email),
              new Date(Date.now() + DAY),
            ],
          );
      }
      const assessment = await this.data.assess(manager, user),
        policy = this.configuredPolicy();
      const durable =
        intent.retention ??
        (assessment.categories.length &&
        !assessment.reason &&
        policy &&
        !intent.completed
          ? await this.durableRetention(
              intent.operationId,
              assessment.categories,
              policy,
            )
          : undefined);
      if (intent.completed && assessment.categories.length && !durable)
        throw new Error('ACCOUNT_DELETION_RETENTION_RECOVERY_REQUIRED');
      if (
        !intent.completed &&
        (assessment.reason || (assessment.categories.length && !durable))
      ) {
        await manager.query(
          "UPDATE core.account_deletion_requests SET status='requires_attention',reason=$2 WHERE request_id=$1",
          [
            intent.operationId,
            assessment.reason ?? 'retention_policy_required',
          ],
        );
        await this.data.minimizePending(
          manager,
          user,
          intent.operationId,
          columns,
        );
        return 'restricted';
      }
      await manager.query(
        "UPDATE core.account_deletion_requests SET status='in_progress' WHERE request_id=$1",
        [intent.operationId],
      );
      if (durable) {
        if (
          assessment.categories.some(
            (category) =>
              !durable.categories.includes(
                category as 'orders' | 'payments' | 'returns',
              ),
          )
        )
          throw new Error('ACCOUNT_DELETION_RETENTION_RECOVERY_REQUIRED');
        const basis =
          policy &&
          this.secrets.hash('retention', intent.operationId, policy.basis) ===
            durable.basisHash
            ? policy.basis
            : 'Conservación previamente autorizada; referencia de integridad ' +
              durable.basisHash;
        await manager.query(
          'INSERT INTO core.account_deletion_retention(request_id,basis,retain_until,categories) VALUES($1,$2,$3,$4::jsonb) ON CONFLICT(request_id) DO NOTHING',
          [
            intent.operationId,
            basis,
            durable.until,
            JSON.stringify(durable.categories),
          ],
        );
      }
      await this.data.purge(manager, user, intent.operationId, columns);
      await manager.query(
        `UPDATE core.account_deletion_requests SET email_hash=NULL,code_hash=NULL,authorization_hash=NULL,
        receipt_hash=CASE WHEN request_id=$2 THEN receipt_hash ELSE '!revoked' END,
        receipt_expires_at=CASE WHEN request_id=$2 THEN receipt_expires_at ELSE clock_timestamp() END WHERE user_id=$1`,
        [user.id_usuario, intent.operationId],
      );
      await manager.query(
        "UPDATE core.account_deletion_accounts SET state='deleted',identity_email=NULL,completed_at=clock_timestamp() WHERE user_id=$1",
        [user.id_usuario],
      );
      await manager.query(
        "UPDATE core.account_deletion_requests SET status='completed',reason=NULL,email_hash=NULL,code_hash=NULL,authorization_hash=NULL,retained_categories=$2::jsonb,notification_status=CASE WHEN EXISTS(SELECT 1 FROM core.account_deletion_notifications WHERE request_id=$1 AND encrypted_recipient IS NOT NULL) THEN 'pending' ELSE notification_status END WHERE request_id=$1",
        [intent.operationId, JSON.stringify(assessment.categories)],
      );
      if (durable && new Date(durable.until).getTime() <= Date.now()) {
        await this.data.expireRetainedIdentifiers(
          manager,
          user.id_usuario,
          columns,
        );
        await manager.query(
          'UPDATE core.account_deletion_retention SET identifiers_expired_at=clock_timestamp() WHERE request_id=$1',
          [intent.operationId],
        );
      }
      return 'completed';
    });
  }
}
