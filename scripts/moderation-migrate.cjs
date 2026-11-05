'use strict';
// La migración versionada también puede ser revisada por el dueño de la base;
// este ejecutable sólo permite su validación en la copia QA local autorizada.
require('ts-node/register/transpile-only');
const {
  moderationMigrationSource,
} = require('../src/database/moderation-data-source');
async function main() {
  const action = process.argv[2];
  if (!['up', 'down'].includes(action))
    throw new Error('MODERATION_MIGRATION_ACTION_REQUIRED');
  const source = moderationMigrationSource();
  try {
    await source.initialize();
    if (action === 'up') await source.runMigrations({ transaction: 'all' });
    else await source.undoLastMigration({ transaction: 'all' });
    process.stdout.write('MODERATION_MIGRATION_QA_COMPLETED\n');
  } finally {
    if (source.isInitialized) await source.destroy();
  }
}
main().catch(() => {
  process.stderr.write('MODERATION_MIGRATION_QA_FAILED\n');
  process.exitCode = 1;
});
