'use strict';
// La migración versionada también puede ser revisada por el dueño de la base;
// este ejecutable sólo permite su validación en la copia QA local autorizada.
require('ts-node/register/transpile-only');
const {
  moderationMigrationSource,
} = require('../src/database/moderation-data-source');
const {
  assertReviewModerationBaseSchema,
} = require('../src/database/migrations/1793740000000-ReviewModeration');
const MIGRATION = 'ReviewModeration1793740000000';
async function ledgerState(source, action) {
  const ledgers = await source.query(`
    SELECT n.nspname AS schema_name,c.relname AS table_name,c.relkind AS relation_kind
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname IN ('core','public')
      AND c.relname IN ('moderation_qa_migrations','review_moderation_migrations');
  `);
  if (
    ledgers.some(
      (row) =>
        row.schema_name !== 'core' ||
        row.table_name !== 'review_moderation_migrations' ||
        row.relation_kind !== 'r',
    )
  )
    throw new Error('MODERATION_MIGRATION_LEDGER_REVIEW_REQUIRED');
  const entries = ledgers.length
    ? await source.query(
        'SELECT name,timestamp::text AS timestamp FROM core.review_moderation_migrations ORDER BY id',
      )
    : [];
  if (action === 'up' && entries.length)
    throw new Error('MODERATION_MIGRATION_ALREADY_RECORDED_REVIEW_REQUIRED');
  if (
    action === 'down' &&
    (entries.length !== 1 ||
      entries[0].name !== MIGRATION ||
      entries[0].timestamp !== '1793740000000')
  )
    throw new Error('MODERATION_MIGRATION_LEDGER_REVIEW_REQUIRED');
}
async function main() {
  const action = process.argv[2];
  if (!['up', 'down'].includes(action))
    throw new Error('MODERATION_MIGRATION_ACTION_REQUIRED');
  const source = moderationMigrationSource();
  try {
    await source.initialize();
    await ledgerState(source, action);
    if (action === 'up') {
      // TypeORM creates its ledger before invoking up(); keep invalid targets read-only.
      await assertReviewModerationBaseSchema(source);
      await source.runMigrations({ transaction: 'all' });
    } else await source.undoLastMigration({ transaction: 'all' });
    process.stdout.write('MODERATION_MIGRATION_QA_COMPLETED\n');
  } finally {
    if (source.isInitialized) await source.destroy();
  }
}
main().catch((error) => {
  const known = new Set([
    'MODERATION_MIGRATION_CORE_SCHEMA_REQUIRED',
    'MODERATION_MIGRATION_PARTIAL_SCHEMA',
    'MODERATION_MIGRATION_LEDGER_REVIEW_REQUIRED',
    'MODERATION_MIGRATION_ALREADY_RECORDED_REVIEW_REQUIRED',
    'MODERATION_MIGRATION_QA_FLAGS_REQUIRED',
    'MODERATION_MIGRATION_QA_DATABASE_REQUIRED',
    'MODERATION_MIGRATION_ACTION_REQUIRED',
  ]);
  process.stderr.write(
    (known.has(error?.message)
      ? error.message
      : 'MODERATION_MIGRATION_QA_FAILED') + '\n',
  );
  process.exitCode = 1;
});
