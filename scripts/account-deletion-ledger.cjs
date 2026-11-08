'use strict';
// Explicit provisioning only. Never creates or replaces a journal during application startup.
const path = require('node:path');
async function main() {
  const action = process.argv[2];
  if (!['init', 'verify'].includes(action)) throw new Error('USE_INIT_OR_VERIFY');
  const key = process.env.ACCOUNT_DELETION_LEDGER_SECRET || '';
  if (!/^[a-f\d]{64}$/i.test(key) || ['JWT_SECRET','JWT_REFRESH_SECRET','ACCOUNT_DELETION_SECRET'].some(name=>key.toLowerCase()===process.env[name]?.toLowerCase())) throw new Error('DEDICATED_LEDGER_KEY_REQUIRED');
  const repositoryRoot = path.resolve(__dirname, '..');
  const compiled = path.join(repositoryRoot, 'dist/src/modules/account-deletion/ledger/file-deletion-ledger.js');
  const { FileDeletionLedger } = require(compiled);
  const ledger = new FileDeletionLedger({ directory: process.env.ACCOUNT_DELETION_LEDGER_DIR || '', repositoryRoot, hmacKey: Buffer.from(key, 'hex') });
  if (action === 'init') await ledger.initializeNew();
  const snapshot = await ledger.verifyAndRead();
  process.stdout.write(JSON.stringify({ status: 'verified', sequence: snapshot.sequence, operations: snapshot.intents.length }) + '\n');
}
if (require.main === module) main().catch(() => { process.stderr.write('ACCOUNT_DELETION_LEDGER_OPERATION_FAILED\n'); process.exitCode = 1; });
