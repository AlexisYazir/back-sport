import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import type { EntityManager } from 'typeorm';
import type { User } from '../users/entities/user.entity';

export interface RetentionPolicy {
  basis: string;
  days: number;
}
type Columns = Map<string, Set<string>>;
const TERMINAL_ORDERS = [
  'entregado',
  'cancelado',
  'rechazado',
  'devuelto',
  'reembolsado',
  'pago_rechazado',
  'pago_cancelado',
];
const TERMINAL_RETURNS = [
  'rechazada',
  'reembolsada',
  'completada',
  'cerrada',
  'cancelada',
];
const fields = (value: string): ReadonlySet<string> =>
  new Set(value.split(/\s+/));
// Verified synthetic QA DDL plus columns explicitly used by current entities/SQL.
// This is NOT a production schema attestation. Adding a column to a handled
// relation requires reviewing its deletion/retention treatment before enabling.
const KNOWN = new Map<string, ReadonlySet<string>>([
  [
    'core.users',
    fields(
      'id_usuario nombre aPaterno aMaterno email telefono passw rol activo token_verificacion token_expiracion intentos_token fecha_creacion fecha_actualizacion email_verified telefono_verified google_id ubicacion',
    ),
  ],
  [
    'core.user_sessions',
    fields(
      'id_sesion id_usuario refresh_token_hash device_name user_agent ip_address creada_en ultima_actividad expira_en revocada_en motivo_revocacion reemplazada_por csrf_token_hash',
    ),
  ],
  [
    'core.carts',
    fields('id_carrito id_usuario estado fecha_creacion fecha_actualizacion'),
  ],
  [
    'core.cart_items',
    fields('id_carrito id_variante cantidad precio_unitario'),
  ],
  [
    'core.direcciones',
    fields(
      'id_direccion id_usuario alias calle numero colonia ciudad estado codigo_postal pais principal fecha_creacion referencias nombre_destinatario telefono latitud longitud',
    ),
  ],
  [
    'core.user_payment_methods',
    fields(
      'id_metodo_pago id_usuario alias marca titular ultimos4 exp_mes exp_anio principal activo fecha_creacion fecha_actualizacion',
    ),
  ],
  [
    'core.reviews',
    fields(
      'id_review id_producto id_usuario calificacion comentario fecha retirada revision',
    ),
  ],
  [
    'core.review_moderation_events',
    fields(
      'id_evento id_review id_mensaje accion motivo id_administrador fecha retirada_anterior retirada_nueva revision',
    ),
  ],
  [
    'core.contact_messages',
    fields(
      'id_mensaje nombre email telefono asunto mensaje leido respondido fecha_lectura id_usuario_responde created_at',
    ),
  ],
  [
    'public.contact_messages',
    fields(
      'id_mensaje nombre email telefono asunto mensaje leido respondido fecha_lectura id_usuario_responde created_at',
    ),
  ],
  [
    'core.orders',
    fields(
      'id_orden id_usuario id_direccion_envio estado subtotal descuento total metodo_pago fecha_pago fecha_envio fecha_entrega fecha_creacion',
    ),
  ],
  [
    'core.order_items',
    fields(
      'id_orden id_variante sku nombre_producto cantidad precio_unitario total',
    ),
  ],
  [
    'core.pagos',
    fields(
      'id_pago id_orden proveedor_pago referencia_externa monto estado fecha_creacion',
    ),
  ],
  [
    'core.shipments',
    fields(
      'id_envio id_orden id_metodo_envio estado numero_guia paqueteria costo_envio fecha_entrega_estimada fecha_entrega codigo_confirmacion_entrega codigo_confirmacion_generado_en codigo_confirmacion_generado_por entrega_confirmada_por_usuario entrega_confirmada_en entrega_validada_por_empleado entrega_validada_en entrega_validada_por creado_por actualizado_por fecha_creacion fecha_actualizacion',
    ),
  ],
  [
    'core.shipment_events',
    fields(
      'id_evento id_envio estado titulo descripcion ubicacion fecha_evento registrado_por',
    ),
  ],
  [
    'core.order_status_history',
    fields(
      'id_historial id_orden estado_anterior estado_nuevo comentario cambiado_por fecha_cambio',
    ),
  ],
  [
    'core.order_discounts',
    fields('id_orden id_promocion codigo descripcion monto'),
  ],
  [
    'core.returns',
    fields(
      'id_devolucion id_orden id_usuario estado motivo descripcion resolucion solicitado_en fecha_actualizacion resuelto_por resuelto_en',
    ),
  ],
  [
    'core.return_items',
    fields(
      'id_item id_devolucion id_orden id_variante cantidad precio_unitario total motivo aprobado',
    ),
  ],
  [
    'core.return_events',
    fields(
      'id_evento id_devolucion estado comentario registrado_por fecha_evento',
    ),
  ],
  [
    'core.promotion_redemptions',
    fields(
      'id_redencion id_promocion id_usuario id_orden codigo_usado descuento_aplicado fecha_redencion',
    ),
  ],
  [
    'core.alexa_codes',
    fields(
      'id_alexa_code id_usuario token_hash purpose expires_at attempts created_at used_at',
    ),
  ],
  [
    'core.alexa_account_links',
    fields(
      'id_link id_usuario alexa_user_id alexa_device_id linked_at last_used_at active',
    ),
  ],
  [
    'core.inventory_movements',
    fields(
      'id_movimiento id_variante tipo cantidad costo_unitario referencia_tipo referencia_id fecha',
    ),
  ],
  [
    'core.account_deletion_accounts',
    fields('user_id account_id state identity_email confirmed_at completed_at'),
  ],
  [
    'core.account_deletion_requests',
    fields(
      'request_id user_id account_id session_id status reason email_hash code_hash code_expires_at attempts authorization_hash authorization_expires_at receipt_hash receipt_expires_at requested_at updated_at retained_categories notification_status',
    ),
  ],
  [
    'core.account_deletion_retention',
    fields(
      'request_id basis retain_until categories identifiers_expired_at created_at',
    ),
  ],
  [
    'core.account_deletion_notifications',
    fields('request_id encrypted_recipient attempts expires_at sent_at'),
  ],
]);
const quote = (value: string): string =>
  '"' + value.replaceAll('"', '""') + '"';
const relation = (value: string): string =>
  value.split('.').map(quote).join('.');

/** Conservative adapter: unknown user relationships stop completion rather than silently orphaning data. */
@Injectable()
export class AccountDeletionDataService {
  private assertKnownColumns(columns: Columns): void {
    for (const [table, present] of columns) {
      const known = KNOWN.get(table);
      if (known && [...present].some((column) => !known.has(column))) {
        throw new Error('ACCOUNT_DELETION_SCHEMA_REVIEW_REQUIRED');
      }
      if (
        !known &&
        ['id_usuario', 'user_id', 'customer_id'].some((column) =>
          present.has(column),
        )
      ) {
        throw new Error('ACCOUNT_DELETION_SCHEMA_REVIEW_REQUIRED');
      }
    }
  }

  async inventory(manager: EntityManager): Promise<Columns> {
    const rows = await manager.query<
      { schema_name: string; table_name: string; column_name: string }[]
    >(`
      SELECT table_schema AS schema_name,table_name,column_name FROM information_schema.columns
      WHERE table_schema IN ('core','public') ORDER BY table_schema,table_name,ordinal_position`);
    const columns: Columns = new Map();
    for (const row of rows) {
      const key = row.schema_name + '.' + row.table_name;
      if (!columns.has(key)) columns.set(key, new Set());
      columns.get(key)!.add(row.column_name);
    }
    this.assertKnownColumns(columns);
    const foreignKeys = await manager.query<
      { schema_name: string; table_name: string }[]
    >(`
      WITH RECURSIVE related(oid) AS (
        SELECT 'core.users'::regclass::oid UNION SELECT c.conrelid FROM pg_constraint c
        JOIN related r ON c.confrelid=r.oid WHERE c.contype='f'
      ) SELECT n.nspname AS schema_name,c.relname AS table_name FROM related r
      JOIN pg_class c ON c.oid=r.oid JOIN pg_namespace n ON n.oid=c.relnamespace`);
    if (
      foreignKeys.some(
        (row) => !KNOWN.has(row.schema_name + '.' + row.table_name),
      )
    )
      throw new Error('ACCOUNT_DELETION_SCHEMA_REVIEW_REQUIRED');
    return columns;
  }

  async assess(
    manager: EntityManager,
    user: User,
  ): Promise<{
    reason: string | null;
    categories: string[];
    columns: Columns;
  }> {
    const columns = await this.inventory(manager),
      categories: string[] = [];
    let reason = user.rol === 1 ? null : 'privileged_account';
    if (columns.has('core.orders')) {
      const orders = await manager.query<{ estado: string }[]>(
        'SELECT estado FROM core.orders WHERE id_usuario=$1 FOR UPDATE',
        [user.id_usuario],
      );
      if (orders.length) categories.push('orders');
      if (
        orders.some(
          (row) => !TERMINAL_ORDERS.includes(row.estado.trim().toLowerCase()),
        )
      )
        reason = 'pending_orders';
      if (columns.has('core.pagos')) {
        const payments = await manager.query<{ estado: string }[]>(
          'SELECT p.estado FROM core.pagos p JOIN core.orders o ON o.id_orden=p.id_orden WHERE o.id_usuario=$1 FOR UPDATE OF p',
          [user.id_usuario],
        );
        if (payments.length) categories.push('payments');
        if (
          payments.some(
            (row) =>
              ![
                'approved',
                'rejected',
                'cancelled',
                'refunded',
                'charged_back',
                'pagado',
                'aprobado',
                'rechazado',
                'cancelado',
                'reembolsado',
              ].includes(row.estado.trim().toLowerCase()),
          )
        )
          reason = 'pending_payments';
      }
      if (columns.has('core.returns')) {
        const returns = await manager.query<{ estado: string }[]>(
          'SELECT r.estado FROM core.returns r JOIN core.orders o ON o.id_orden=r.id_orden WHERE o.id_usuario=$1 FOR UPDATE OF r',
          [user.id_usuario],
        );
        if (returns.length) categories.push('returns');
        if (
          returns.some(
            (row) =>
              !TERMINAL_RETURNS.includes(row.estado.trim().toLowerCase()),
          )
        )
          reason = 'pending_returns';
      }
    }
    return { reason, categories, columns };
  }

  async purge(
    manager: EntityManager,
    user: User,
    requestId: string,
    columns: Columns,
  ): Promise<void> {
    await this.purgeInternal(manager, user, requestId, columns, false);
  }

  async minimizePending(
    manager: EntityManager,
    user: User,
    requestId: string,
    columns: Columns,
  ): Promise<void> {
    await this.purgeInternal(manager, user, requestId, columns, true);
  }

  private async purgeInternal(
    manager: EntityManager,
    user: User,
    requestId: string,
    columns: Columns,
    preserveDeliveryDetails: boolean,
  ): Promise<void> {
    this.assertKnownColumns(columns);
    const id = user.id_usuario;
    await manager.query(
      "SELECT set_config('sportcenter.account_deletion',$1,true)",
      [requestId],
    );
    const anchors = await manager.query<{ identity_email: string | null }[]>(
      'SELECT identity_email FROM core.account_deletion_accounts WHERE user_id=$1',
      [id],
    );
    const emails = [
      ...new Set(
        [user.email, ...anchors.map((row) => row.identity_email)]
          .filter(
            (email): email is string =>
              typeof email === 'string' && !!email.trim(),
          )
          .map((email) => email.trim().toLowerCase()),
      ),
    ];
    if (columns.has('core.carts')) {
      if (columns.has('core.cart_items'))
        await manager.query(
          'DELETE FROM core.cart_items WHERE id_carrito IN (SELECT id_carrito FROM core.carts WHERE id_usuario=$1)',
          [id],
        );
      await manager.query('DELETE FROM core.carts WHERE id_usuario=$1', [id]);
    }
    for (const table of [
      'core.user_payment_methods',
      'core.alexa_codes',
      'core.alexa_account_links',
    ]) {
      const fields = columns.get(table);
      if (!fields) continue;
      const owner = fields.has('id_usuario')
        ? 'id_usuario'
        : fields.has('user_id')
          ? 'user_id'
          : null;
      if (!owner) throw new Error('ACCOUNT_DELETION_SCHEMA_REVIEW_REQUIRED');
      await manager.query(
        `DELETE FROM ${relation(table)} WHERE ${quote(owner)}=$1`,
        [id],
      );
    }
    if (columns.has('core.review_moderation_events'))
      await manager.query(
        "UPDATE core.review_moderation_events SET motivo='Contenido eliminado por su titular' WHERE id_review IN (SELECT id_review FROM core.reviews WHERE id_usuario=$1)",
        [id],
      );
    if (columns.has('core.reviews'))
      await manager.query(
        "UPDATE core.reviews SET comentario='Contenido eliminado por su autor' WHERE id_usuario=$1",
        [id],
      );
    // Only the narrowly authorized privacy redaction may update moderation
    // history. IDs, decisions, revisions and chronology remain unchanged.
    for (const table of ['core.contact_messages', 'public.contact_messages']) {
      if (columns.has(table) && emails.length)
        await manager.query(
          `UPDATE ${relation(table)} SET nombre='Cuenta eliminada',email='',telefono=NULL,asunto='Datos eliminados',mensaje='Contenido eliminado por su titular' WHERE lower(btrim(email))=ANY($1::text[])`,
          [emails],
        );
    }
    if (columns.has('core.direcciones')) {
      if (columns.has('core.orders'))
        await manager.query(
          'DELETE FROM core.direcciones d WHERE d.id_usuario=$1 AND NOT EXISTS(SELECT 1 FROM core.orders o WHERE o.id_direccion_envio=d.id_direccion)',
          [id],
        );
      else
        await manager.query(
          'DELETE FROM core.direcciones WHERE id_usuario=$1',
          [id],
        );
      const fields = columns.get('core.direcciones')!;
      const personal = [
        'alias',
        'calle',
        'numero',
        'colonia',
        'ciudad',
        'estado',
        'codigo_postal',
        'pais',
        'referencias',
        'nombre_destinatario',
        'telefono',
        'latitud',
        'longitud',
      ].filter((field) => fields.has(field));
      const numeric = new Set(['latitud', 'longitud']);
      const protectPending =
        preserveDeliveryDetails && columns.has('core.orders');
      const protectReturns = protectPending && columns.has('core.returns');
      const pendingOrderOrReturn = protectPending
        ? " AND NOT EXISTS(SELECT 1 FROM core.orders o WHERE o.id_direccion_envio=d.id_direccion AND (COALESCE(lower(btrim(o.estado)),'')<>ALL($2::text[])" +
          (protectReturns
            ? " OR EXISTS(SELECT 1 FROM core.returns r WHERE r.id_orden=o.id_orden AND COALESCE(lower(btrim(r.estado)),'')<>ALL($3::text[]))"
            : '') +
          '))'
        : '';
      if (personal.length)
        await manager.query(
          `UPDATE core.direcciones d SET ${personal.map((field) => quote(field) + '=' + (numeric.has(field) ? 'NULL' : "''")).join(',')},principal=false WHERE d.id_usuario=$1${pendingOrderOrReturn}`,
          protectPending
            ? protectReturns
              ? [id, TERMINAL_ORDERS, TERMINAL_RETURNS]
              : [id, TERMINAL_ORDERS]
            : [id],
        );
    }
    if (preserveDeliveryDetails) {
      await manager.query(
        'DELETE FROM core.user_sessions WHERE id_usuario=$1',
        [id],
      );
      await manager.query(
        `UPDATE core.users SET passw=$2,activo=0,token_verificacion=NULL,
        token_expiracion=NULL,intentos_token=0,email_verified=0,telefono_verified=0,
        google_id=NULL,ubicacion=NULL,fecha_actualizacion=clock_timestamp() WHERE id_usuario=$1`,
        [id, '!deleted:' + randomBytes(32).toString('hex')],
      );
      return;
    }
    // Financial values and identifiers remain; delivery codes and free text no longer serve the account.
    if (columns.has('core.shipments')) {
      const fields = columns.get('core.shipments')!;
      if (fields.has('codigo_confirmacion_entrega'))
        await manager.query(
          'UPDATE core.shipments SET codigo_confirmacion_entrega=NULL WHERE id_orden IN (SELECT id_orden FROM core.orders WHERE id_usuario=$1)',
          [id],
        );
    }
    for (const [table, owner] of [
      ['core.order_status_history', 'id_orden'],
      ['core.shipment_events', 'id_envio'],
      ['core.return_events', 'id_devolucion'],
      ['core.returns', 'id_orden'],
      ['core.return_items', 'id_devolucion'],
    ] as const) {
      const fields = columns.get(table);
      if (!fields) continue;
      const texts = [
        'comentario',
        'descripcion',
        'ubicacion',
        'motivo',
        'observaciones',
        'resolucion',
      ].filter((field) => fields.has(field));
      const ownerQuery =
        owner === 'id_orden'
          ? 'SELECT id_orden FROM core.orders WHERE id_usuario=$1'
          : owner === 'id_envio'
            ? 'SELECT id_envio FROM core.shipments WHERE id_orden IN (SELECT id_orden FROM core.orders WHERE id_usuario=$1)'
            : 'SELECT id_devolucion FROM core.returns WHERE id_orden IN (SELECT id_orden FROM core.orders WHERE id_usuario=$1)';
      if (texts.length)
        await manager.query(
          `UPDATE ${relation(table)} SET ${texts.map((field) => quote(field) + "='Contenido eliminado'").join(',')} WHERE ${quote(owner)} IN (${ownerQuery})`,
          [id],
        );
    }
    await manager.query('DELETE FROM core.user_sessions WHERE id_usuario=$1', [
      id,
    ]);
    await manager.query(
      `UPDATE core.users SET nombre='Cuenta eliminada',"aPaterno"='',"aMaterno"='',
      email=NULL,telefono=NULL,passw=$2,activo=0,token_verificacion=NULL,token_expiracion=NULL,intentos_token=0,
      email_verified=0,telefono_verified=0,google_id=NULL,ubicacion=NULL,fecha_actualizacion=clock_timestamp()
      WHERE id_usuario=$1`,
      [id, '!deleted:' + randomBytes(32).toString('hex')],
    );
  }

  /** Final identifier minimization after the explicitly recorded legal period. */
  async expireRetainedIdentifiers(
    manager: EntityManager,
    userId: number,
    columns: Columns,
  ): Promise<void> {
    this.assertKnownColumns(columns);
    const allowed = await manager.query<{ request_id: string }[]>(
      `SELECT r.request_id FROM core.account_deletion_retention t
      JOIN core.account_deletion_requests r USING(request_id)
      JOIN core.account_deletion_accounts a ON a.user_id=r.user_id
      WHERE a.user_id=$1 AND a.state='deleted' AND r.status='completed'
        AND t.retain_until<=clock_timestamp() FOR UPDATE OF t`,
      [userId],
    );
    if (!Number.isSafeInteger(userId) || userId <= 0 || allowed.length !== 1) {
      throw new Error('ACCOUNT_DELETION_EXPIRY_NOT_AUTHORIZED');
    }
    await manager.query(
      "SELECT set_config('sportcenter.account_deletion',$1,true)",
      [allowed[0].request_id],
    );
    if (columns.has('core.pagos')) {
      const present = columns.get('core.pagos')!;
      if (
        !present.has('id_pago') ||
        !present.has('id_orden') ||
        !present.has('referencia_externa')
      ) {
        throw new Error('ACCOUNT_DELETION_SCHEMA_REVIEW_REQUIRED');
      }
      await manager.query(
        `UPDATE core.pagos p SET referencia_externa='deleted:'||p.id_pago::text
        WHERE p.id_orden IN (SELECT id_orden FROM core.orders WHERE id_usuario=$1)`,
        [userId],
      );
    }
    const shipmentFields = columns.get('core.shipments');
    if (shipmentFields) {
      const identifiers = ['numero_guia', 'paqueteria'].filter((field) =>
        shipmentFields.has(field),
      );
      if (identifiers.length)
        await manager.query(
          `UPDATE core.shipments SET ${identifiers.map((field) => quote(field) + '=NULL').join(',')}
        WHERE id_orden IN (SELECT id_orden FROM core.orders WHERE id_usuario=$1)`,
          [userId],
        );
    }
  }
}
