import { moderationMigrationSource } from './moderation-data-source';

describe('Runner explícito de migración de moderación', () => {
  const env = {
    ISOLATED_TEST_ENV: 'true',
    QA_REVIEW_MODERATION: 'true',
    DATABASE_URL_ADMIN: 'postgres://admin:synthetic@db:5432/sportcenter_qa',
  };
  test('prepara sólo QA sin conectar ni activar synchronize', () => {
    const source = moderationMigrationSource(env);
    expect(source.isInitialized).toBe(false);
    expect(source.options.synchronize).toBe(false);
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
});
