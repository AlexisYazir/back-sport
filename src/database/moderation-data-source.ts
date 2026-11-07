import { DataSource } from 'typeorm';
import { ReviewModeration1793740000000 } from './migrations/1793740000000-ReviewModeration';

// Runner explícito para QA. No carga .env ni admite una URL de producción.
export function moderationMigrationSource(
  env: NodeJS.ProcessEnv = process.env,
): DataSource {
  if (env.ISOLATED_TEST_ENV !== 'true' || env.QA_REVIEW_MODERATION !== 'true')
    throw new Error('MODERATION_MIGRATION_QA_FLAGS_REQUIRED');
  let target: URL;
  try {
    target = new URL(env.DATABASE_URL_ADMIN ?? '');
    const password = decodeURIComponent(target.password);
    if (
      !password.trim() ||
      [...password].some((character) => {
        const code = character.charCodeAt(0);
        return code < 32 || code === 127;
      })
    )
      throw new Error();
  } catch {
    throw new Error('MODERATION_MIGRATION_QA_DATABASE_REQUIRED');
  }
  if (
    !['postgres:', 'postgresql:'].includes(target.protocol) ||
    target.hostname !== '127.0.0.1' ||
    target.username !== 'qa_admin' ||
    !target.port ||
    Number(target.port) < 1024 ||
    Number(target.port) > 65535 ||
    target.pathname !== '/sportcenter_moderation_qa' ||
    target.search ||
    target.hash
  )
    throw new Error('MODERATION_MIGRATION_QA_DATABASE_REQUIRED');
  return new DataSource({
    type: 'postgres',
    url: target.toString(),
    ssl: false,
    synchronize: false,
    schema: 'core',
    migrations: [ReviewModeration1793740000000],
    migrationsTableName: 'review_moderation_migrations',
    migrationsTransactionMode: 'all',
    extra: { connectionTimeoutMillis: 5000, statement_timeout: 15000 },
  });
}
