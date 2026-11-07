import { getMetadataArgsStorage } from 'typeorm';
import type { QueryRunner } from 'typeorm';
import { ContactMessage } from '../../modules/company/entities/contact-message.entity';
import {
  assertReviewModerationBaseSchema,
  ReviewModeration1793740000000,
} from './1793740000000-ReviewModeration';

type Column = {
  schema_name: string;
  table_name: string;
  relation_kind: string;
  column_name: string;
  type_oid: number;
  primary_key: boolean;
};
function catalog(): Column[] {
  const tables: [string, [string, number][]][] = [
    [
      'users',
      [
        ['id_usuario', 23],
        ['nombre', 1043],
        ['email', 1043],
        ['rol', 23],
        ['activo', 23],
      ],
    ],
    [
      'reviews',
      [
        ['id_review', 23],
        ['id_producto', 23],
        ['id_usuario', 23],
        ['calificacion', 23],
        ['comentario', 25],
        ['fecha', 1114],
      ],
    ],
    [
      'contact_messages',
      [
        ['id_mensaje', 23],
        ['nombre', 1043],
        ['email', 1043],
        ['telefono', 1043],
        ['asunto', 1043],
        ['mensaje', 25],
        ['leido', 16],
        ['respondido', 16],
        ['fecha_lectura', 1114],
        ['id_usuario_responde', 23],
        ['created_at', 1114],
      ],
    ],
  ];
  return tables.flatMap(([table, columns]) =>
    columns.map(([column, type], index) => ({
      schema_name: 'core',
      table_name: table,
      relation_kind: 'r',
      column_name: column,
      type_oid: type,
      primary_key: index === 0,
    })),
  );
}
function source(rows: unknown = catalog(), artifacts = false) {
  const query = jest
    .fn<Promise<unknown>, [string]>()
    .mockResolvedValueOnce(rows)
    .mockResolvedValueOnce([{ present: artifacts }])
    .mockResolvedValue([]);
  return { query };
}
const mutations = (q: ReturnType<typeof source>) =>
  q.query.mock.calls.filter(([sql]) =>
    /\b(?:ALTER|CREATE|DROP|GRANT|REVOKE)\b/i.test(sql),
  );

describe('Preflight de moderación con esquema core explícito', () => {
  test('la entidad no depende del search_path', () => {
    expect(
      getMetadataArgsStorage().tables.find(
        (row) => row.target === ContactMessage,
      ),
    ).toMatchObject({ name: 'contact_messages', schema: 'core' });
  });
  test('el preflight válido sólo lee metadatos', async () => {
    const q = source();
    await expect(assertReviewModerationBaseSchema(q)).resolves.toBeUndefined();
    expect(mutations(q)).toEqual([]);
  });
  test('up crea la FK sólo después del preflight y hacia core', async () => {
    const q = source();
    await new ReviewModeration1793740000000().up(q as unknown as QueryRunner);
    expect(mutations(q)).toHaveLength(1);
    expect(mutations(q)[0][0]).toContain(
      'REFERENCES core.contact_messages(id_mensaje)',
    );
    expect(mutations(q)[0][0]).not.toContain('public.contact_messages');
    expect(q.query.mock.calls[0][0]).toContain('pg_catalog.pg_namespace');
  });
  const invalid: [string, (rows: Column[]) => Column[]][] = [
    ['sin tablas', () => []],
    ...['users', 'reviews', 'contact_messages'].map(
      (table): [string, (rows: Column[]) => Column[]] => [
        'sin ' + table,
        (rows) => rows.filter((row) => row.table_name !== table),
      ],
    ),
    [
      'public-only',
      (rows) => rows.map((row) => ({ ...row, schema_name: 'public' })),
    ],
    [
      'contactos duplicados',
      (rows) => [
        ...rows,
        ...rows
          .filter((row) => row.table_name === 'contact_messages')
          .map((row) => ({ ...row, schema_name: 'public' })),
      ],
    ],
    [
      'vista en vez de tabla',
      (rows) =>
        rows.map((row) =>
          row.table_name === 'contact_messages'
            ? { ...row, relation_kind: 'v' }
            : row,
        ),
    ],
    [
      'ID incompatible',
      (rows) =>
        rows.map((row) =>
          row.table_name === 'contact_messages' &&
          row.column_name === 'id_mensaje'
            ? { ...row, type_oid: 20 }
            : row,
        ),
    ],
    [
      'sin email del contacto',
      (rows) =>
        rows.filter(
          (row) =>
            !(
              row.table_name === 'contact_messages' &&
              row.column_name === 'email'
            ),
        ),
    ],
    [
      'flag incompatible',
      (rows) =>
        rows.map((row) =>
          row.column_name === 'respondido' ? { ...row, type_oid: 25 } : row,
        ),
    ],
    ...['users', 'reviews', 'contact_messages'].map(
      (table): [string, (rows: Column[]) => Column[]] => [
        'sin PK de ' + table,
        (rows) =>
          rows.map((row) =>
            row.table_name === table ? { ...row, primary_key: false } : row,
          ),
      ],
    ),
  ];
  test.each(invalid)('rechaza %s antes de DDL', async (_label, change) => {
    const q = source(change(catalog()));
    await expect(
      new ReviewModeration1793740000000().up(q as unknown as QueryRunner),
    ).rejects.toThrow('MODERATION_MIGRATION_CORE_SCHEMA_REQUIRED');
    expect(mutations(q)).toEqual([]);
  });
  test.each([
    ['retirada', 'reviews', 16],
    ['revision', 'reviews', 23],
    ['id_evento', 'review_moderation_events', 23],
  ] as const)('rechaza instalación parcial %s', async (column, table, type) => {
    const q = source([
      ...catalog(),
      {
        schema_name: 'core',
        table_name: table,
        relation_kind: 'r',
        column_name: column,
        type_oid: type,
        primary_key: false,
      },
    ]);
    await expect(
      new ReviewModeration1793740000000().up(q as unknown as QueryRunner),
    ).rejects.toThrow('MODERATION_MIGRATION_PARTIAL_SCHEMA');
    expect(mutations(q)).toEqual([]);
  });
  test('rechaza funciones huérfanas sin ALTER', async () => {
    const q = source(catalog(), true);
    await expect(
      new ReviewModeration1793740000000().up(q as unknown as QueryRunner),
    ).rejects.toThrow('MODERATION_MIGRATION_PARTIAL_SCHEMA');
    expect(mutations(q)).toEqual([]);
  });
  test('admite columnas ajenas sin afirmar paridad total', async () => {
    const q = source([
      ...catalog(),
      {
        schema_name: 'core',
        table_name: 'contact_messages',
        relation_kind: 'r',
        column_name: 'legacy_note',
        type_oid: 25,
        primary_key: false,
      },
    ]);
    await expect(assertReviewModerationBaseSchema(q)).resolves.toBeUndefined();
  });
  test.each([null, {}, [null], [42]])(
    'rechaza metadatos inválidos %#',
    async (rows) => {
      const q = source(rows);
      await expect(assertReviewModerationBaseSchema(q)).rejects.toThrow(
        'MODERATION_MIGRATION_CORE_SCHEMA_REQUIRED',
      );
      expect(mutations(q)).toEqual([]);
    },
  );
});
