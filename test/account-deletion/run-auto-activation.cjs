'use strict';
// Real, fresh PostgreSQL18; the R2 transport and mail are synthetic captures.
// This never imports AppModule, starts cron jobs or contacts a shared service.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { createRequire } = require('node:module');
const { execFileSync } = require('node:child_process');
assert.ok(process.argv.includes('--execute'), 'EXPLICIT_QA_EXECUTE_REQUIRED');
assert.ok(process.env.PG_BINDIR && path.isAbsolute(process.env.PG_BINDIR), 'PG_BINDIR_REQUIRED');
assert.ok(!process.env.ACCOUNT_DELETION_QA_ROOT, 'FRESH_QA_ROOT_REQUIRED');
process.env.ACCOUNT_DELETION_QA_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'sportcenter-deletion-auto-qa-'));
process.env.ACCOUNT_DELETION_POSTGRES_QA = 'true';
const { command, env, BASE, DB, USER, sha } = require('./postgres-runtime.cjs');
const SOURCE = path.resolve(__dirname, '../..');
const deps = createRequire(path.join(SOURCE, 'package.json'));
const schemaOption = process.argv.indexOf('--schema-only-file');
const liveSchemaFile = schemaOption < 0 ? null : process.argv[schemaOption + 1];
assert.ok(liveSchemaFile === null || (typeof liveSchemaFile === 'string' && path.isAbsolute(liveSchemaFile)), 'SCHEMA_ONLY_ABSOLUTE_FILE_REQUIRED');
const liveSchema = liveSchemaFile === null ? null : fs.readFileSync(liveSchemaFile);
if (liveSchema) {
  // Explicitly approved, schema-only source: no customer records are imported.
  assert.equal(sha(liveSchema), '8df6b846a35abcd82a1f23a837fe1c432f4473ecbb1923fa2ba11bfde89c77a3', 'APPROVED_SCHEMA_ONLY_HASH_REQUIRED');
  assert.ok(!/^COPY /m.test(liveSchema.toString('utf8')), 'SCHEMA_ONLY_NO_COPY_REQUIRED');
  assert.ok(!/^INSERT INTO /m.test(liveSchema.toString('utf8')), 'SCHEMA_ONLY_NO_DATA_INSERT_REQUIRED');
}
// Fail closed before loading application code if it attempts provider traffic.
const net = require('node:net');
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const input = args[0];
  const options = input && typeof input === 'object' ? input : { host: typeof args[1] === 'string' ? args[1] : '127.0.0.1' };
  assert.ok(['127.0.0.1', '::1'].includes(options.host ?? '127.0.0.1') && !options.path, 'QA_LOOPBACK_ONLY');
  return connect.apply(this, args);
};
for (const method of ['request', 'get']) {
  const http = require('node:http');
  const original = http[method];
  http[method] = function (input, ...args) {
    const target = typeof input === 'string' || input instanceof URL ? new URL(input) : input;
    assert.ok(['127.0.0.1', '::1'].includes(target.hostname ?? target.host), 'QA_HTTP_LOOPBACK_ONLY');
    return original.call(this, input, ...args);
  };
  require('node:https')[method] = () => { throw new Error('QA_HTTPS_DISABLED'); };
}
global.fetch = () => Promise.reject(new Error('QA_FETCH_DISABLED'));
deps('reflect-metadata');
deps('ts-node').register({ project: path.join(SOURCE, 'tsconfig.json'), transpileOnly: true, compilerOptions: { incremental: false } });
const { DataSource } = deps('typeorm');
const { ConfigService } = deps('@nestjs/config');
const { Client } = deps('pg');
const { S3Client, GetObjectCommand, PutObjectCommand } = deps('@aws-sdk/client-s3');
const { User } = require(path.join(SOURCE, 'src/modules/users/entities/user.entity.ts'));
const { ReviewModeration1793740000000 } = require(path.join(SOURCE, 'src/database/migrations/1793740000000-ReviewModeration.ts'));
const { AccountDeletionActivationService } = require(path.join(SOURCE, 'src/modules/account-deletion/account-deletion-activation.service.ts'));
const { AccountDeletionService } = require(path.join(SOURCE, 'src/modules/account-deletion/account-deletion.service.ts'));
const { AccountDeletionDataService } = require(path.join(SOURCE, 'src/modules/account-deletion/account-deletion-data.service.ts'));
const { AccountDeletionAccessService } = require(path.join(SOURCE, 'src/modules/account-deletion/account-deletion-access.service.ts'));
const { DeletionSecrets } = require(path.join(SOURCE, 'src/modules/account-deletion/deletion-secrets.ts'));
const { DeletionRecoveryGate } = require(path.join(SOURCE, 'src/modules/account-deletion/deletion-recovery-gate.ts'));
const { AccountDeletionBootstrapService } = require(path.join(SOURCE, 'src/modules/account-deletion/account-deletion-bootstrap.service.ts'));
const { JwtStrategy } = require(path.join(SOURCE, 'src/services/auth/jwt.strategy.ts'));
const objects = new Map();
let revision = 0;
const originalSend = S3Client.prototype.send;
S3Client.prototype.send = async function (command) {
  const input = command.input;
  assert.equal(input.Bucket, 'synthetic-deletion-qa');
  assert.match(input.Key, /^_account-deletion\/v1\/[a-f\d]{64}\/[a-z\d.-]+$/);
  const stored = objects.get(input.Key);
  if (command instanceof GetObjectCommand) {
    if (!stored) throw Object.assign(new Error('SYNTHETIC_MISSING_KEY'), { name: 'NoSuchKey', $metadata: { httpStatusCode: 404 } });
    return { ETag: stored.etag, ContentLength: Buffer.byteLength(stored.body), Body: require('node:stream').Readable.from([Buffer.from(stored.body)]) };
  }
  assert.ok(command instanceof PutObjectCommand, 'UNEXPECTED_S3_COMMAND');
  assert.ok(input.IfNoneMatch === '*' || typeof input.IfMatch === 'string', 'CONDITIONAL_WRITE_REQUIRED');
  if ((input.IfNoneMatch === '*' && stored) || (input.IfMatch && input.IfMatch !== stored?.etag)) {
    throw Object.assign(new Error('SYNTHETIC_CAS_CONFLICT'), { name: 'PreconditionFailed', $metadata: { httpStatusCode: 412 } });
  }
  // Each call commits atomically before yielding, matching the conditional contract.
  const body = Buffer.isBuffer(input.Body) ? input.Body.toString('utf8') : String(input.Body);
  const etag = '"' + createHash('sha256').update(body + ':' + (++revision)).digest('hex') + '"';
  objects.set(input.Key, { body, etag });
  return { ETag: etag };
};
const save = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
const principal = id => ({ id_usuario: id, sessionId: '71000000-0000-4000-8000-' + String(id).padStart(12, '0'), rol: 1 });
const connection = port => ({ host: '127.0.0.1', port, database: DB, user: USER, password: 'qa-admin-local', ssl: false, statement_timeout: 15000, query_timeout: 18000 });

async function main() {
  // Git's Windows checkout can represent the pinned DDL with CRLF. Prepare a
  // new, normalized QA copy without overwriting any source or pending change.
  const baselineDirectory = path.join(BASE, 'baseline-runtime');
  fs.mkdirSync(baselineDirectory);
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8').replace(/\r\n/g, '\n');
  assert.equal(sha(Buffer.from(schema, 'utf8')), '4d91e9a467de9cdab15afbad76f9770b11e65ecff86727f5a1b2dcb24ab54203', 'QA_BASELINE_SCHEMA_CHANGED');
  fs.writeFileSync(path.join(baselineDirectory, 'schema.sql'), schema, { flag: 'wx' });
  fs.copyFileSync(path.join(__dirname, 'postgres-runtime.cjs'), path.join(baselineDirectory, 'postgres-runtime.cjs'), fs.constants.COPYFILE_EXCL);
  const output = execFileSync(process.execPath, [path.join(baselineDirectory, 'postgres-runtime.cjs')], { cwd: BASE, env, windowsHide: true, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60000 });
  const baseline = JSON.parse(output.trim().split(/\r?\n/).at(-1));
  assert.equal(baseline.status, 'passed');
  assert.equal(baseline.stopped, true);
  const run = baseline.run;
  const metadata = JSON.parse(fs.readFileSync(path.join(run, 'baseline-result.json'), 'utf8'));
  assert.equal(path.dirname(run), BASE);
  const report = { scope: 'fresh-native-postgresql18-auto-activation-synthetic-R2-and-mail-not-production', schema: liveSchema ? 'approved-live-schema-only-no-original-records' : 'historical-synthetic-schema', schemaSha256: liveSchema ? sha(liveSchema) : null, status: 'failed', run, checks: [], networkGuard: 'loopback-only-provider-traffic-disabled', sharedDatabaseTouched: false, externalServicesUsed: false, stopped: false, harnessSha256: sha(fs.readFileSync(__filename)) };
  const checked = name => { report.checks.push({ name, status: 'passed' }); fs.appendFileSync(path.join(run, 'auto-activation-progress.jsonl'), JSON.stringify({ name }) + '\n', { mode: 0o600 }); };
  let started = false;
  let client;
  const sources = new Set();
  const createSource = async (role = USER) => {
    const source = new DataSource({ type: 'postgres', host: '127.0.0.1', port: metadata.port, database: DB, username: role, password: role === USER ? 'qa-admin-local' : role === 'qa_editor' ? 'qa-editor-local' : 'qa-runtime-local', ssl: false, entities: [User], synchronize: false, logging: false, extra: { max: 3, statement_timeout: 15000, query_timeout: 18000 } });
    await source.initialize();
    sources.add(source);
    return source;
  };
  const newConfig = (overrides = {}) => {
    const config = new ConfigService({ DATABASE_URL_ADMIN: `postgresql://${USER}:qa-admin-local@127.0.0.1:${metadata.port}/${DB}?sslmode=require`, DATABASE_URL_BACKUP: `postgresql://qa_backup:qa-backup-local@127.0.0.1:${metadata.port}/${DB}?sslmode=require`, JWT_SECRET: 'synthetic-qa-existing-long-jwt-secret-with-stable-purpose', JWT_REFRESH_SECRET: 'synthetic-qa-existing-distinct-refresh-secret', R2_ENDPOINT: 'https://qa-storage.invalid', R2_ACCESS_KEY_ID: 'synthetic-access', R2_SECRET_ACCESS_KEY: 'synthetic-secret', R2_BUCKET: 'synthetic-deletion-qa', FRONTEND_URL: 'http://localhost:4200', ...overrides });
    config.skipProcessEnv = true;
    return config;
  };
  const mail = { codes: [], results: [], async sendAccountDeletionCode(email, code) { assert.ok(email.endsWith('@qa.invalid')); this.codes.push({ email, code }); }, async sendAccountDeletionResult(email, requestId) { assert.ok(email.endsWith('@qa.invalid')); this.results.push({ email, requestId }); } };
  const data = new AccountDeletionDataService();
  // This adapter deliberately invokes the production class, not a reimplementation.
  const activate = async (source, config) => {
    const activation = new AccountDeletionActivationService(source, config, data);
    const ledger = await activation.prepare();
    return { activation, ledger, config };
  };
  const readyService = async (source, config, ledger) => {
    const gate = new DeletionRecoveryGate(true, ledger);
    const service = new AccountDeletionService(source, config, new DeletionSecrets(config), data, mail, ledger, gate);
    const bootstrap = new AccountDeletionBootstrapService(gate, service);
    await bootstrap.prepare();
    gate.assertApplicationReady();
    return { gate, service };
  };
  const closedSources = async () => { for (const source of sources) if (source.isInitialized) await source.destroy(); sources.clear(); };
  try {
    command('pg_ctl', ['-D', metadata.dataDirectory, '-l', path.join(run, 'auto-activation-postgres.log'), '-o', ' -h 127.0.0.1 -p ' + metadata.port + ' -c shared_buffers=32MB -c max_connections=20 -c log_statement=none -c log_min_error_statement=panic', '-w', '-t', '15', 'start'], { stdio: 'ignore', timeout: 20000 });
    started = true;
    client = new Client(connection(metadata.port));
    await client.connect();
    const identity = (await client.query("SELECT current_database() database,current_user username,host(inet_server_addr()) host,inet_server_port() port,current_setting('data_directory') directory")).rows[0];
    assert.equal(identity.database, DB); assert.equal(identity.username, USER); assert.equal(identity.host, '127.0.0.1'); assert.equal(identity.port, metadata.port); assert.equal(path.resolve(identity.directory), path.resolve(metadata.dataDirectory));
    report.identity = identity;
    if (liveSchema) {
      // This is the only destructive operation, confined to the just-created,
      // identity-checked cluster/database; all prior QA evidence remains.
      await client.end(); client = null;
      const admin = new Client({ ...connection(metadata.port), database: 'postgres' }); await admin.connect();
      try {
        const own = (await admin.query("SELECT host(inet_server_addr()) host,inet_server_port() port,current_setting('data_directory') directory")).rows[0];
        assert.equal(own.host, '127.0.0.1'); assert.equal(own.port, metadata.port); assert.equal(path.resolve(own.directory), path.resolve(metadata.dataDirectory));
        await admin.query('DROP DATABASE sportcenter_deletion_qa WITH (FORCE)');
        await admin.query('CREATE DATABASE sportcenter_deletion_qa');
      } finally { await admin.end(); }
      command('psql', ['-X', '-v', 'ON_ERROR_STOP=1', '--no-password', '-h', '127.0.0.1', '-p', String(metadata.port), '-U', USER, '-d', DB], { env: { ...env, PGPASSWORD: 'qa-admin-local' }, input: liveSchema, maxBuffer: 8 * 1024 * 1024 });
      client = new Client(connection(metadata.port)); await client.connect();
      const emptyTables = (await client.query("SELECT schemaname,relname,n_live_tup FROM pg_stat_user_tables")).rows;
      assert.ok(emptyTables.every(row => Number(row.n_live_tup) === 0));
      await client.query('GRANT USAGE ON SCHEMA core,public TO qa_editor,qa_reader,qa_backup; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA core,public TO qa_editor; GRANT SELECT ON ALL TABLES IN SCHEMA core,public TO qa_reader,qa_backup; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA core,public TO qa_editor; GRANT SELECT ON ALL SEQUENCES IN SCHEMA core,public TO qa_backup');
      await client.query("INSERT INTO core.roles(id_rol,rol) OVERRIDING SYSTEM VALUE VALUES(1,'Cliente'),(3,'Administrador')");
      await client.query(`INSERT INTO core.users(id_usuario,nombre,"aPaterno","aMaterno",email,passw,rol,activo,email_verified) OVERRIDING SYSTEM VALUE VALUES(710101,'QA','Sintetica','Aislada','deletion-710101@qa.invalid','synthetic-no-real-password-hash',1,1,1)`);
      await client.query("INSERT INTO core.user_sessions(id_sesion,id_usuario,refresh_token_hash,expira_en) VALUES($1,710101,'synthetic-qa-first-refresh',clock_timestamp()+interval '1 hour'),('72000000-0000-4000-8000-000000710101',710101,'synthetic-qa-second-refresh',clock_timestamp()+interval '1 hour')", [principal(710101).sessionId]);
      const columns = (await client.query("SELECT table_name,column_name,is_nullable FROM information_schema.columns WHERE table_schema='core' AND ((table_name='users' AND column_name='email') OR (table_name='shipments' AND column_name IN ('notas','tracking_url')) OR (table_name='return_items' AND column_name='condicion_producto')) ORDER BY table_name,column_name")).rows;
      assert.equal(columns.length, 4); assert.ok(columns.every(row => row.is_nullable === 'YES'));
      report.realSchemaConstraintColumns = columns;
      checked('approved-live-DDL-imported-with-zero-original-records-and-real-nullability-intact');
    } else {
      await client.query(fs.readFileSync(path.join(__dirname, 'fixtures.sql'), 'utf8'));
      const runner = { query: async (sql, args) => (await client.query(sql, args)).rows };
      await client.query('BEGIN'); await new ReviewModeration1793740000000().up(runner); await client.query('COMMIT');
      await client.query('CREATE TABLE public.contact_messages (LIKE core.contact_messages INCLUDING ALL)');
    }
    const archive = path.join(run, 'pre-feature-synthetic.dump');
    const dump = command('pg_dump', ['-h', '127.0.0.1', '-p', String(metadata.port), '-U', USER, '-d', DB, '--format=custom', '--no-owner'], { env: { ...env, PGPASSWORD: 'qa-admin-local' }, encoding: null, maxBuffer: 32 * 1024 * 1024 });
    fs.writeFileSync(archive, dump, { flag: 'wx', mode: 0o600 });
    report.preFeatureArchiveSha256 = sha(dump);
    let source = await createSource();
    await client.query('ALTER TABLE core.users ADD COLUMN unexpected_personal_qa text');
    await assert.rejects(activate(source, newConfig()));
    assert.equal((await client.query("SELECT to_regclass('core.account_deletion_accounts')::text value")).rows[0].value, null);
    await client.query('ALTER TABLE core.users DROP COLUMN unexpected_personal_qa');
    checked('unknown-personal-column-refuses-automatic-migration-without-partial-schema');
    await client.query('CREATE TABLE core.account_deletion_requests(request_id uuid)');
    await assert.rejects(activate(source, newConfig()));
    assert.equal((await client.query("SELECT to_regclass('core.account_deletion_accounts')::text value")).rows[0].value, null);
    await client.query('DROP TABLE core.account_deletion_requests');
    checked('preexisting-partial-feature-schema-is-rejected-without-overwrite');
    await client.query('CREATE TABLE core.account_deletion_accounts(user_id integer); CREATE TABLE core.account_deletion_requests(request_id uuid); CREATE TABLE core.account_deletion_retention(request_id uuid); CREATE TABLE core.account_deletion_notifications(request_id uuid)');
    await assert.rejects(activate(source, newConfig()), /ACCOUNT_DELETION_UNVERIFIED_SCHEMA/);
    assert.equal((await client.query("SELECT to_regclass('core.account_deletion_installation')::text value")).rows[0].value, null);
    await client.query('DROP TABLE core.account_deletion_accounts,core.account_deletion_requests,core.account_deletion_retention,core.account_deletion_notifications');
    checked('four-existing-tables-without-verified-installation-marker-are-not-adopted');
    await assert.rejects(activate(source, newConfig({ DATABASE_URL_BACKUP: `postgresql://qa_editor:qa-editor-local@127.0.0.1:${metadata.port}/${DB}?sslmode=require` })));
    assert.equal((await client.query("SELECT count(*)::integer value FROM pg_tables WHERE schemaname='core' AND tablename IN ('account_deletion_accounts','account_deletion_requests','account_deletion_notifications','account_deletion_retention','account_deletion_installation')")).rows[0].value, 0);
    checked('invalid-writer-backup-role-rolls-back-all-feature-DDL-and-installation-marker');
    const other = await createSource();
    const [first, second] = await Promise.all([activate(source, newConfig()), activate(other, newConfig())]);
    assert.ok(first.ledger && second.ledger);
    assert.equal(first.config.get('ACCOUNT_DELETION_ENABLED'), 'true');
    assert.equal(second.config.get('ACCOUNT_DELETION_ENABLED'), 'true');
    for (const key of ['ACCOUNT_DELETION_SECRET', 'ACCOUNT_DELETION_LEDGER_SECRET']) { assert.match(first.config.get(key), /^[a-f\d]{64}$/); assert.equal(first.config.get(key), second.config.get(key)); }
    assert.notEqual(first.config.get('ACCOUNT_DELETION_SECRET'), first.config.get('ACCOUNT_DELETION_LEDGER_SECRET'));
    checked('two-independent-startups-automatically-migrate-once-and-reuse-independent-secrets');
    const legacyDisabled = await activate(source, newConfig({ ACCOUNT_DELETION_ENABLED: 'false' }));
    assert.equal(legacyDisabled.config.get('ACCOUNT_DELETION_ENABLED'), 'true');
    await readyService(source, legacyDisabled.config, legacyDisabled.ledger);
    assert.equal((await legacyDisabled.ledger.verifyAndRead()).digest, (await first.ledger.verifyAndRead()).digest);
    checked('legacy-false-flag-cannot-bypass-external-history-or-reconciliation-when-R2-is-configured');
    await client.query("CREATE ROLE qa_runtime_admin LOGIN PASSWORD 'qa-runtime-local'; GRANT USAGE ON SCHEMA core,public TO qa_runtime_admin; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA core,public TO qa_runtime_admin; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA core,public TO qa_runtime_admin");
    assert.equal((await client.query("SELECT has_schema_privilege('qa_runtime_admin','core','CREATE') allowed")).rows[0].allowed, false);
    const restricted = await createSource('qa_runtime_admin');
    const restrictedActivation = await activate(restricted, newConfig({ DATABASE_URL_ADMIN: `postgresql://qa_runtime_admin:qa-runtime-local@127.0.0.1:${metadata.port}/${DB}?sslmode=require` }));
    assert.equal(restrictedActivation.config.get('ACCOUNT_DELETION_SECRET'), first.config.get('ACCOUNT_DELETION_SECRET'));
    await readyService(restricted, restrictedActivation.config, restrictedActivation.ledger);
    checked('runtime-admin-without-schema-create-or-table-ownership-reuses-owner-provisioned-installation');
    for (const role of ['qa_reader', 'qa_editor']) for (const table of ['account_deletion_requests', 'account_deletion_retention', 'account_deletion_notifications']) assert.equal((await client.query("SELECT has_table_privilege($1,$2,'SELECT') allowed", [role, 'core.' + table])).rows[0].allowed, false);
    for (const table of ['account_deletion_accounts', 'account_deletion_requests', 'account_deletion_retention', 'account_deletion_notifications']) assert.equal((await client.query("SELECT has_table_privilege('qa_backup',$1,'SELECT') allowed", ['core.' + table])).rows[0].allowed, true);
    const editor = await createSource('qa_editor');
    const access = new AccountDeletionAccessService(editor, first.config);
    await access.assertAllowed(710101);
    const strategy = new JwtStrategy(first.config, { isSessionActive: async id => { const rows = await source.query('SELECT 1 FROM core.user_sessions WHERE id_sesion=$1 AND revocada_en IS NULL AND expira_en>clock_timestamp()', [id]); return rows.length === 1; } }, access);
    const oldToken = { id_usuario: 710101, sessionId: principal(710101).sessionId, rol: 1, email: 'deletion-710101@qa.invalid' };
    assert.equal((await strategy.validate(oldToken)).id_usuario, 710101);
    checked('existing-verified-account-and-session-still-authenticate-after-automatic-installation');
    const { service } = await readyService(source, first.config, first.ledger);
    const request = await service.request(principal(710101));
    assert.equal(request.status, 'received'); assert.equal((await service.result(request.requestId, request.receiptToken)).status, 'received');
    const code = mail.codes.at(-1).code; assert.match(code, /^\d{6}$/);
    const verified = await service.verify(principal(710101), request.requestId, code);
    assert.equal((await service.result(request.requestId, request.receiptToken)).status, 'identity_verified');
    const deletion = await service.confirm(principal(710101), request.requestId, verified.confirmationToken, true);
    assert.equal(deletion.status, 'completed');
    await assert.rejects(strategy.validate(oldToken), error => error.getStatus() === 401);
    assert.equal((await client.query('SELECT count(*)::integer count FROM core.user_sessions WHERE id_usuario=710101 AND revocada_en IS NULL')).rows[0].count, 0);
    const ledgerBefore = await first.ledger.verifyAndRead(); assert.ok(ledgerBefore.intents.some(item => item.operationId === request.requestId && item.completed));
    checked('real-service-six-digit-verification-confirmation-completes-and-revokes-all-sessions');
    await closedSources(); await client.end(); client = null;
    const admin = new Client({ ...connection(metadata.port), database: 'postgres' }); await admin.connect();
    try { const own = (await admin.query("SELECT host(inet_server_addr()) host,inet_server_port() port,current_setting('data_directory') directory")).rows[0]; assert.equal(own.host, '127.0.0.1'); assert.equal(own.port, metadata.port); assert.equal(path.resolve(own.directory), path.resolve(metadata.dataDirectory)); await admin.query('DROP DATABASE sportcenter_deletion_qa WITH (FORCE)'); await admin.query('CREATE DATABASE sportcenter_deletion_qa'); } finally { await admin.end(); }
    command('pg_restore', ['-h', '127.0.0.1', '-p', String(metadata.port), '-U', USER, '-d', DB, '--no-owner', '--exit-on-error', archive], { env: { ...env, PGPASSWORD: 'qa-admin-local' }, timeout: 45000 });
    client = new Client(connection(metadata.port)); await client.connect();
    assert.equal((await client.query('SELECT activo FROM core.users WHERE id_usuario=710101')).rows[0].activo, 1);
    source = await createSource();
    const restored = await activate(source, newConfig());
    await readyService(source, restored.config, restored.ledger);
    assert.equal((await client.query('SELECT state FROM core.account_deletion_accounts WHERE user_id=710101')).rows[0].state, 'deleted');
    assert.equal((await client.query('SELECT email FROM core.users WHERE id_usuario=710101')).rows[0].email, null);
    const restoredEditor = await createSource('qa_editor');
    await assert.rejects(new AccountDeletionAccessService(restoredEditor, restored.config).assertAllowed(710101), error => error.getStatus() === 401);
    assert.equal((await client.query('SELECT count(*)::integer count FROM core.user_sessions WHERE id_usuario=710101 AND revocada_en IS NULL')).rows[0].count, 0);
    checked('restore-of-pre-feature-backup-automatically-reinstalls-and-replays-external-ledger-before-serving');
    await client.query(`INSERT INTO core.users(id_usuario,nombre,"aPaterno","aMaterno",email,passw,rol,activo,email_verified) OVERRIDING SYSTEM VALUE VALUES(710300,'Nueva','Cuenta','QA','deletion-710101@qa.invalid','synthetic-new-hash',1,1,1)`);
    const fresh = (await client.query('SELECT account_id,state FROM core.account_deletion_accounts WHERE user_id=710300')).rows[0];
    assert.equal(fresh.state, 'active'); assert.notEqual(fresh.account_id, ledgerBefore.intents[0].accountId);
    await new AccountDeletionAccessService(restoredEditor, restored.config).assertAllowed(710300);
    checked('same-email-can-register-a-new-independent-identity-without-restoring-deleted-data');
    const snapshotKey = [...objects.keys()].find(key => /snapshot/.test(key)); assert.ok(snapshotKey);
    const snapshot = objects.get(snapshotKey); objects.delete(snapshotKey);
    await assert.rejects(activate(source, newConfig()));
    assert.equal(objects.has(snapshotKey), false);
    objects.set(snapshotKey, snapshot);
    checked('missing-active-remote-snapshot-is-never-reinitialized-after-history');
    const restarted = await activate(source, newConfig()); await readyService(source, restarted.config, restarted.ledger);
    assert.equal((await restarted.ledger.verifyAndRead()).digest, (await restored.ledger.verifyAndRead()).digest);
    checked('ordinary-restart-is-idempotent-without-manual-environment-changes');
    report.status = 'passed';
  } catch (error) {
    report.errorCode = String(error.code || error.name || 'ERROR');
    fs.writeFileSync(path.join(run, 'auto-activation-failure-private.log'), String(error.stack || error) + '\n' + String(error.stdout || '') + '\n' + String(error.stderr || ''), { flag: 'wx', mode: 0o600 });
    throw error;
  } finally {
    await closedSources().catch(() => {}); if (client) await client.end().catch(() => {});
    if (started) try { command('pg_ctl', ['-D', metadata.dataDirectory, '-m', 'fast', '-w', '-t', '15', 'stop'], { stdio: 'ignore', timeout: 20000 }); report.stopped = true; } catch { report.stopped = false; }
    S3Client.prototype.send = originalSend;
    save(path.join(run, 'auto-activation-result.json'), report);
    process.stdout.write(JSON.stringify({ run, status: report.status, checks: report.checks.length, stopped: report.stopped }) + '\n');
  }
}
main().catch(error => {
  fs.writeFileSync(path.join(BASE, 'activation-harness-failure-private.log'), String(error.stack || error) + '\n' + String(error.stdout || '') + '\n' + String(error.stderr || ''), { flag: 'wx', mode: 0o600 });
  process.stderr.write('AUTO_ACTIVATION_QA_FAILED_PRIVATE_LOG_SAVED ' + BASE + '\n');
  process.exitCode = 1;
});
