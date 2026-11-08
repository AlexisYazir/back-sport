import type { EntityManager } from 'typeorm';
import type { User } from '../users/entities/user.entity';
import { AccountDeletionDataService } from './account-deletion-data.service';

type Tables = Record<string, string[]>;
const user = { id_usuario: 17, rol: 1, email: 'owner@example.test' } as User;
const requestId = '53aeeb29-9404-43f4-846f-97d982cb2e22';
const basic: Tables = {
  'core.users': ['id_usuario', 'nombre', 'email', 'passw'],
  'core.user_sessions': ['id_sesion', 'id_usuario', 'refresh_token_hash'],
};

function fixture(
  tables: Tables = basic,
  options: {
    related?: { schema_name: string; table_name: string }[];
    orders?: readonly string[];
    payments?: readonly string[];
    returns?: readonly string[];
    expiryAllowed?: boolean;
    identityEmail?: string;
  } = {},
) {
  const columns = new Map(
    Object.entries(tables).map(([table, names]) => [table, new Set(names)]),
  );
  const metadata = Object.entries(tables).flatMap(([table, names]) => {
    const [schema_name, table_name] = table.split('.');
    return names.map((column_name) => ({
      schema_name,
      table_name,
      column_name,
    }));
  });
  const query = jest
    .fn<Promise<unknown[]>, [string, unknown[]?]>()
    .mockImplementation((sql) => {
      if (sql.includes('information_schema.columns'))
        return Promise.resolve(metadata);
      if (sql.includes('WITH RECURSIVE'))
        return Promise.resolve(
          options.related ?? [{ schema_name: 'core', table_name: 'users' }],
        );
      if (
        sql.startsWith(
          'SELECT identity_email FROM core.account_deletion_accounts',
        )
      )
        return Promise.resolve(
          options.identityEmail
            ? [{ identity_email: options.identityEmail }]
            : [],
        );
      if (sql.includes('SELECT estado FROM core.orders'))
        return Promise.resolve(
          (options.orders ?? []).map((estado) => ({ estado })),
        );
      if (sql.includes('SELECT p.estado'))
        return Promise.resolve(
          (options.payments ?? []).map((estado) => ({ estado })),
        );
      if (sql.includes('SELECT r.estado'))
        return Promise.resolve(
          (options.returns ?? []).map((estado) => ({ estado })),
        );
      if (
        sql.includes('SELECT r.request_id FROM core.account_deletion_retention')
      )
        return Promise.resolve(
          options.expiryAllowed ? [{ request_id: requestId }] : [],
        );
      return Promise.resolve([]);
    });
  return {
    columns,
    query,
    manager: { query } as unknown as EntityManager,
    service: new AccountDeletionDataService(),
  };
}

describe('AccountDeletionDataService', () => {
  test('inventories schema metadata without selecting additional personal data', async () => {
    const { service, manager, query } = fixture({
      ...basic,
      'public.contact_messages': ['id_mensaje', 'email', 'mensaje'],
    });
    expect(
      (await service.inventory(manager)).has('public.contact_messages'),
    ).toBe(true);
    expect(query.mock.calls).toHaveLength(2);
    expect(query.mock.calls[0][0]).toContain('information_schema.columns');
    expect(query.mock.calls[1][0]).toContain('pg_constraint');
  });

  test.each([
    { ...basic, 'core.users': ['id_usuario', 'email', 'extra_personal'] },
    {
      ...basic,
      'core.orders': ['id_orden', 'id_usuario', 'customer_document'],
    },
    { ...basic, 'core.account_deletion_extension': ['user_id', 'email'] },
    { ...basic, 'public.orders': ['id_orden', 'id_usuario'] },
    { ...basic, 'core.unhandled': ['customer_id', 'notes'] },
  ])(
    'rejects unreviewed personal columns or owner relationships before purging',
    async (tables) => {
      const { service, manager, query, columns } = fixture(tables);
      await expect(service.inventory(manager)).rejects.toThrow(
        'SCHEMA_REVIEW_REQUIRED',
      );
      expect(query.mock.calls).toHaveLength(1);
      query.mockClear();
      await expect(
        service.purge(manager, user, requestId, columns),
      ).rejects.toThrow('SCHEMA_REVIEW_REQUIRED');
      expect(query).not.toHaveBeenCalled();
    },
  );

  test('rejects an unknown FK descendant even with a harmless-looking name', async () => {
    const { service, manager } = fixture(basic, {
      related: [{ schema_name: 'other_schema', table_name: 'orders' }],
    });
    await expect(service.inventory(manager)).rejects.toThrow(
      'SCHEMA_REVIEW_REQUIRED',
    );
  });

  test('finished purchases are retained categories, not a pending-order block', async () => {
    const { service, manager } = fixture(
      {
        ...basic,
        'core.orders': ['id_orden', 'id_usuario', 'estado'],
        'core.pagos': ['id_pago', 'id_orden', 'estado'],
        'core.returns': ['id_devolucion', 'id_orden', 'estado'],
      },
      {
        orders: ['entregado', 'pago_rechazado', 'PAGO_CANCELADO'],
        payments: ['aprobado', 'reembolsado'],
        returns: ['cerrada'],
      },
    );
    await expect(service.assess(manager, user)).resolves.toMatchObject({
      reason: null,
      categories: ['orders', 'payments', 'returns'],
    });
  });

  test('pending delivery, payment and return require the corresponding review', async () => {
    const tables = {
      ...basic,
      'core.orders': ['id_orden', 'id_usuario', 'estado'],
      'core.pagos': ['id_pago', 'id_orden', 'estado'],
      'core.returns': ['id_devolucion', 'id_orden', 'estado'],
    };
    for (const [options, reason] of [
      [{ orders: ['preparando'] }, 'pending_orders'],
      [{ orders: ['entregado'], payments: ['pendiente'] }, 'pending_payments'],
      [{ orders: ['entregado'], returns: ['solicitada'] }, 'pending_returns'],
    ] as const) {
      const { service, manager } = fixture(tables, options);
      expect((await service.assess(manager, user)).reason).toBe(reason);
    }
  });

  test('moderation reasons are redacted, not classified as commercial retention', async () => {
    const { service, manager } = fixture({
      ...basic,
      'core.reviews': ['id_review', 'id_usuario', 'comentario'],
      'core.review_moderation_events': ['id_evento', 'id_review', 'motivo'],
    });
    expect((await service.assess(manager, user)).categories).toEqual([]);
  });

  test('full purge scopes free text, credentials and content to this account while preserving financial rows', async () => {
    const tables = {
      ...basic,
      'core.carts': ['id_carrito', 'id_usuario'],
      'core.cart_items': ['id_carrito', 'id_variante'],
      'core.direcciones': ['id_direccion', 'id_usuario', 'calle', 'principal'],
      'core.orders': ['id_orden', 'id_usuario', 'id_direccion_envio'],
      'core.returns': [
        'id_devolucion',
        'id_orden',
        'motivo',
        'descripcion',
        'resolucion',
      ],
      'core.return_items': ['id_devolucion', 'id_orden', 'motivo'],
      'core.return_events': ['id_devolucion', 'comentario'],
      'core.reviews': ['id_review', 'id_usuario', 'comentario'],
      'core.review_moderation_events': ['id_review', 'motivo'],
      'core.contact_messages': ['id_mensaje', 'email', 'nombre', 'mensaje'],
    };
    const { service, manager, query, columns } = fixture(tables);
    await service.purge(manager, user, requestId, columns);
    const calls = query.mock.calls;
    expect(calls[0]).toEqual([
      expect.stringContaining("set_config('sportcenter.account_deletion'"),
      [requestId],
    ]);
    const moderation = calls.findIndex(([sql]) =>
      sql.startsWith('UPDATE core.review_moderation_events'),
    );
    const reviews = calls.findIndex(([sql]) =>
      sql.startsWith('UPDATE core.reviews'),
    );
    expect(moderation).toBeGreaterThan(0);
    expect(moderation).toBeLessThan(reviews);
    expect(calls[moderation]).toEqual([
      expect.stringContaining("motivo='Contenido eliminado por su titular'"),
      [user.id_usuario],
    ]);
    for (const table of [
      'core.returns',
      'core.return_items',
      'core.return_events',
    ]) {
      expect(calls).toContainEqual([
        expect.stringContaining('UPDATE "' + table.replace('.', '"."') + '"'),
        [user.id_usuario],
      ]);
    }
    expect(
      calls.find(([sql]) => sql.startsWith('UPDATE "core"."returns"'))?.[0],
    ).toContain('"resolucion"=');
    const sql = calls.map(([statement]) => statement).join('\n');
    expect(sql).not.toMatch(
      /DELETE FROM core\.(orders|pagos|order_items|returns)/,
    );
    expect(sql).not.toContain('DELETE FROM core.review_moderation_events');
    expect(sql).not.toMatch(/SET\s+(monto|total|subtotal)\s*=/);
    const account = calls.find(([statement]) =>
      statement.startsWith('UPDATE core.users'),
    );
    expect(account?.[1]?.[0]).toBe(user.id_usuario);
    expect(account?.[1]?.[1]).toMatch(/^!deleted:[a-f\d]{64}$/);
  });

  test('pending minimization removes access and unrelated content, preserving only delivery contact and pending addresses', async () => {
    const { service, manager, query, columns } = fixture({
      ...basic,
      'core.orders': ['id_orden', 'id_usuario', 'id_direccion_envio', 'estado'],
      'core.direcciones': ['id_direccion', 'id_usuario', 'calle', 'principal'],
      'core.user_payment_methods': ['id_usuario', 'titular'],
      'core.alexa_codes': ['id_usuario', 'token_hash'],
      'core.alexa_account_links': ['id_usuario', 'alexa_user_id'],
      'core.reviews': ['id_usuario', 'comentario'],
    });
    await service.minimizePending(manager, user, requestId, columns);
    const sql = query.mock.calls.map(([statement]) => statement).join('\n');
    expect(sql).toContain('DELETE FROM core.user_sessions');
    expect(sql).toContain('DELETE FROM "core"."user_payment_methods"');
    expect(sql).toContain('DELETE FROM "core"."alexa_account_links"');
    expect(sql).toContain('UPDATE core.reviews');
    const update = query.mock.calls.find(([statement]) =>
      statement.startsWith('UPDATE core.users'),
    )?.[0];
    expect(update).toContain('google_id=NULL');
    expect(update).not.toMatch(/email=NULL|telefono=NULL|nombre=/);
    const address = query.mock.calls.find(([statement]) =>
      statement.startsWith('UPDATE core.direcciones'),
    );
    expect(address?.[0]).toContain('NOT EXISTS');
    expect(address?.[0]).toContain('o.id_direccion_envio=d.id_direccion');
    expect(address?.[1]?.[0]).toBe(user.id_usuario);
    expect(address?.[1]?.[1]).toEqual(
      expect.arrayContaining(['entregado', 'pago_rechazado']),
    );
    expect(sql).not.toContain('UPDATE core.pagos');
  });

  test('contact redaction covers the current email and immutable verified anchor without selecting message contents', async () => {
    const { service, manager, query, columns } = fixture(
      {
        ...basic,
        'public.contact_messages': ['id_mensaje', 'email', 'mensaje'],
      },
      { identityEmail: ' Previous@Example.test ' },
    );
    await service.purge(manager, user, requestId, columns);
    const update = query.mock.calls.find(([sql]) =>
      sql.startsWith('UPDATE "public"."contact_messages"'),
    );
    expect(update?.[1]).toEqual([
      ['owner@example.test', 'previous@example.test'],
    ]);
    expect(update?.[0]).toContain('lower(btrim(email))=ANY($1::text[])');
    expect(
      query.mock.calls.some(([sql]) => sql.startsWith('SELECT mensaje')),
    ).toBe(false);
  });

  test('pending return preserves its delivered order address, while final purge removes that exception', async () => {
    const { service, manager, query, columns } = fixture(
      {
        ...basic,
        'core.orders': [
          'id_orden',
          'id_usuario',
          'id_direccion_envio',
          'estado',
        ],
        'core.direcciones': [
          'id_direccion',
          'id_usuario',
          'calle',
          'principal',
        ],
        'core.returns': ['id_devolucion', 'id_orden', 'id_usuario', 'estado'],
      },
      { orders: ['entregado'], returns: ['solicitada'] },
    );
    expect((await service.assess(manager, user)).reason).toBe(
      'pending_returns',
    );
    query.mockClear();
    await service.minimizePending(manager, user, requestId, columns);
    const pending = query.mock.calls.find(([sql]) =>
      sql.startsWith('UPDATE core.direcciones'),
    );
    expect(pending?.[0]).toContain(
      'OR EXISTS(SELECT 1 FROM core.returns r WHERE r.id_orden=o.id_orden',
    );
    expect(pending?.[0]).toContain(
      "COALESCE(lower(btrim(r.estado)),'')<>ALL($3::text[])",
    );
    expect(pending?.[1]).toEqual([
      user.id_usuario,
      expect.arrayContaining(['entregado']),
      expect.arrayContaining(['cerrada', 'reembolsada', 'cancelada']),
    ]);
    query.mockClear();
    await service.purge(manager, user, requestId, columns);
    const final = query.mock.calls.find(([sql]) =>
      sql.startsWith('UPDATE core.direcciones'),
    );
    expect(final?.[0]).not.toContain('NOT EXISTS');
    expect(final?.[0]).not.toContain('core.returns');
    expect(final?.[1]).toEqual([user.id_usuario]);
  });

  test('return item redaction follows its return parent without requiring an id_orden column on the item', async () => {
    const { service, manager, query, columns } = fixture({
      ...basic,
      'core.returns': ['id_devolucion', 'id_orden', 'descripcion'],
      'core.return_items': ['id_devolucion', 'motivo'],
    });
    await service.purge(manager, user, requestId, columns);
    const update = query.mock.calls.find(([sql]) =>
      sql.startsWith('UPDATE "core"."return_items"'),
    );
    expect(update?.[0]).toContain(
      'WHERE "id_devolucion" IN (SELECT id_devolucion FROM core.returns',
    );
    expect(update?.[0]).toContain(
      'SELECT id_orden FROM core.orders WHERE id_usuario=$1',
    );
    expect(update?.[1]).toEqual([user.id_usuario]);
  });

  test('expired identifiers require a completed deleted account and an expired recorded policy', async () => {
    const { service, manager, query, columns } = fixture({
      ...basic,
      'core.pagos': ['id_pago', 'id_orden', 'referencia_externa'],
    });
    await expect(
      service.expireRetainedIdentifiers(manager, user.id_usuario, columns),
    ).rejects.toThrow('EXPIRY_NOT_AUTHORIZED');
    expect(query.mock.calls).toHaveLength(1);
    expect(query.mock.calls[0][0]).toContain("a.state='deleted'");
    expect(query.mock.calls[0][0]).toContain("r.status='completed'");
    expect(query.mock.calls[0][0]).toContain(
      't.retain_until<=clock_timestamp()',
    );
  });

  test('expiry scrubs only this account identifiers, retaining payment amounts and other accounts', async () => {
    const { service, manager, query, columns } = fixture(
      {
        ...basic,
        'core.pagos': ['id_pago', 'id_orden', 'referencia_externa', 'monto'],
        'core.shipments': ['id_envio', 'id_orden', 'numero_guia', 'paqueteria'],
      },
      { expiryAllowed: true },
    );
    await service.expireRetainedIdentifiers(manager, user.id_usuario, columns);
    const mutations = query.mock.calls.filter(([sql]) =>
      sql.startsWith('UPDATE'),
    );
    expect(mutations).toHaveLength(2);
    expect(mutations[0][0]).toContain(
      "referencia_externa='deleted:'||p.id_pago::text",
    );
    expect(mutations[1][0]).toContain('"numero_guia"=NULL');
    for (const [sql, parameters] of mutations) {
      expect(sql).toContain(
        'SELECT id_orden FROM core.orders WHERE id_usuario=$1',
      );
      expect(parameters).toEqual([user.id_usuario]);
      expect(sql).not.toMatch(/monto\s*=|total\s*=|estado\s*=/);
    }
  });
});
