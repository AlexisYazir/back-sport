import { DataSource } from 'typeorm';
import { ReviewModeration1793740000000 } from './migrations/1793740000000-ReviewModeration';

// Runner explícito para QA. No carga .env ni admite una URL de producción.
export function moderationMigrationSource(
  env: NodeJS.ProcessEnv = process.env,
): DataSource {
  if (env.ISOLATED_TEST_ENV !== 'true' || env.QA_REVIEW_MODERATION !== 'true')
    throw new Error('MODERATION_MIGRATION_QA_FLAGS_REQUIRED');
  const target = new URL(env.DATABASE_URL_ADMIN ?? '');
  if (
    !['postgres:', 'postgresql:'].includes(target.protocol) ||
    !['localhost', '127.0.0.1', 'db'].includes(target.hostname) ||
    target.pathname !== '/sportcenter_qa' ||
    target.search ||
    target.hash
  )
    throw new Error('MODERATION_MIGRATION_QA_DATABASE_REQUIRED');
  return new DataSource({
    type: 'postgres',
    url: target.toString(),
    ssl: false,
    synchronize: false,
    migrations: [ReviewModeration1793740000000],
    migrationsTableName: 'review_moderation_migrations',
    migrationsTransactionMode: 'all',
    extra: { connectionTimeoutMillis: 5000, statement_timeout: 15000 },
  });
}
