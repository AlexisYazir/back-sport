import { moderationMigrationSource } from './moderation-data-source';

describe('Runner explícito de migración de moderación', () => {
  const env = {
    ISOLATED_TEST_ENV: 'true',
    QA_REVIEW_MODERATION: 'true',
    DATABASE_URL_ADMIN:
      'postgres://qa_admin:synthetic@127.0.0.1:15432/sportcenter_moderation_qa',
  };
  test('prepara sólo QA sin conectar ni activar synchronize', () => {
    const source = moderationMigrationSource(env);
    expect(source.isInitialized).toBe(false);
    expect(source.options.synchronize).toBe(false);
    expect(source.options.type).toBe('postgres');
    expect('schema' in source.options && source.options.schema).toBe('core');
    expect(source.options.migrationsTableName).toBe(
      'review_moderation_migrations',
    );
    expect(source.options.migrationsTransactionMode).toBe('all');
    expect(source.options.migrations).toHaveLength(1);
  });
  test.each([
    { ISOLATED_TEST_ENV: 'false' },
    { QA_REVIEW_MODERATION: 'false' },
    {
      DATABASE_URL_ADMIN:
        'postgres://synthetic@production.invalid/sportcenter_qa',
    },
    { DATABASE_URL_ADMIN: 'postgres://synthetic@db/production' },
    {
      DATABASE_URL_ADMIN:
        'postgres://synthetic@db/sportcenter_qa?host=remote.invalid',
    },
  ])(
    'rechaza configuración fuera del alcance local autorizado: %p',
    (change) => {
      expect(() => moderationMigrationSource({ ...env, ...change })).toThrow(
        /MODERATION_MIGRATION_QA_/,
      );
    },
  );

  test.each([1024, 65535])(
    'acepta el puerto QA explícito %i sin conectar',
    (port) => {
      const source = moderationMigrationSource({
        ...env,
        DATABASE_URL_ADMIN: env.DATABASE_URL_ADMIN.replace(
          ':15432/',
          ':' + port + '/',
        ),
      });
      expect(source.isInitialized).toBe(false);
    },
  );

  test.each([
    [
      'host db no acreditado',
      env.DATABASE_URL_ADMIN.replace('127.0.0.1', 'db'),
    ],
    [
      'localhost no numérico',
      env.DATABASE_URL_ADMIN.replace('127.0.0.1', 'localhost'),
    ],
    ['puerto implícito', env.DATABASE_URL_ADMIN.replace(':15432/', '/')],
    ['puerto privilegiado', env.DATABASE_URL_ADMIN.replace(':15432/', ':543/')],
    [
      'puerto fuera de rango',
      env.DATABASE_URL_ADMIN.replace(':15432/', ':65536/'),
    ],
    ['rol ajeno', env.DATABASE_URL_ADMIN.replace('qa_admin:', 'admin:')],
    [
      'rol codificado',
      env.DATABASE_URL_ADMIN.replace('qa_admin:', 'qa%5Fadmin:'),
    ],
    ['sin contraseña', env.DATABASE_URL_ADMIN.replace(':synthetic@', '@')],
    ['contraseña vacía', env.DATABASE_URL_ADMIN.replace(':synthetic@', ':@')],
    [
      'contraseña sólo espacios',
      env.DATABASE_URL_ADMIN.replace(':synthetic@', ':%20@'),
    ],
    [
      'control en contraseña',
      env.DATABASE_URL_ADMIN.replace(':synthetic@', ':%00@'),
    ],
    [
      'base anterior',
      env.DATABASE_URL_ADMIN.replace(
        'sportcenter_moderation_qa',
        'sportcenter_qa',
      ),
    ],
    [
      'query que sustituye host',
      env.DATABASE_URL_ADMIN + '?host=outside.invalid',
    ],
    ['fragmento', env.DATABASE_URL_ADMIN + '#outside'],
    ['URL inválida', 'not-a-database-url'],
  ])('rechaza %s antes de conectar', (_label, url) => {
    expect(() =>
      moderationMigrationSource({ ...env, DATABASE_URL_ADMIN: url }),
    ).toThrow('MODERATION_MIGRATION_QA_DATABASE_REQUIRED');
  });
});
