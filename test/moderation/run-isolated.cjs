'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const ROOT = path.resolve(__dirname, '../..');
const COMPOSE = path.join(__dirname, 'compose.yml');
const PG =
  'postgres@sha256:5fe8ca7fc662071188c30271cb870d1ce9a6ec4578c934b064697ae77a9241e1';
const SECRET = 'moderation-qa-not-a-production-secret';
const FILES = [
  'src/modules/products/products.controller.ts',
  'src/modules/products/products.service.ts',
  'src/modules/products/services/product-review-moderation.service.ts',
  'src/modules/products/services/product-reviews.service.ts',
  'src/modules/products/dto/reviews/moderation.dto.ts',
  'src/modules/products/entities/reviews/review.entity.ts',
  'src/modules/products/entities/reviews/review-moderation-event.entity.ts',
  'src/database/migrations/1793740000000-ReviewModeration.ts',
  'src/database/moderation-data-source.ts',
  'scripts/moderation-migrate.cjs',
  'src/modules/company/company.controller.ts',
  'src/modules/company/company.service.ts',
  'src/modules/company/entities/contact-message.entity.ts',
  'src/modules/company/dto/update-contact-message.dto.ts',
  'src/services/auth/active-admin.guard.ts',
  'src/services/auth/jwt.strategy.ts',
  'src/services/auth/roles.guard.ts',
  'test/moderation.e2e-spec.ts',
  'test/jest-moderation.json',
  'test/moderation/schema.sql',
  'test/moderation/compose.yml',
  'test/moderation/run-isolated.cjs',
  'test/moderation/network-guard.cjs',
  'package-lock.json',
];
const hashes = () =>
  Object.fromEntries(
    FILES.map((file) => [
      file,
      crypto
        .createHash('sha256')
        .update(fs.readFileSync(path.join(ROOT, file)))
        .digest('hex'),
    ]),
  );
function guard(config) {
  assert.match(config.name, /^sportcenter-moderation-qa-\d+$/);
  assert.deepEqual(Object.keys(config.services), ['db']);
  assert.notEqual(config.networks.isolated.internal, true);
  const db = config.services.db;
  assert.equal(db.image, PG);
  assert.deepEqual(Object.keys(db.networks), ['isolated']);
  assert.equal(db.environment.POSTGRES_DB, 'sportcenter_moderation_qa');
  assert.equal(db.environment.POSTGRES_USER, 'qa_admin');
  assert.equal(db.ports.length, 1);
  assert.equal(db.ports[0].host_ip, '127.0.0.1');
  assert.equal(db.ports[0].target, 5432);
  assert.ok(!db.ports[0].published || db.ports[0].published === '0');
  assert.ok(
    !Object.keys(db.environment).some((key) =>
      /TOKEN|MERCADO_PAGO|AWS|SMTP|MAIL_PASSWORD|EMAIL_PASS/i.test(key),
    ),
  );
}
function testEnvironment(port) {
  assert.match(String(port), /^\d+$/);
  assert.ok(Number(port) >= 1024 && Number(port) <= 65535);
  const env = systemEnvironment();
  delete env.DOCKER_CONFIG;
  Object.assign(env, {
    NODE_ENV: 'test',
    MODERATION_QA: 'true',
    MODERATION_QA_PORT: String(port),
    JWT_SECRET: SECRET,
    NODE_OPTIONS: '--require="' + path.join(__dirname, 'network-guard.cjs').replace(/\\/g, '/') + '"',
  });
  for (const role of ['ADMIN', 'EDITOR', 'READER'])
    env['DATABASE_URL_' + role] =
      'postgres://qa_' +
      role.toLowerCase() +
      ':qa-' +
      role.toLowerCase() +
      '-local@127.0.0.1:' +
      port +
      '/sportcenter_moderation_qa';
  return env;
}
function systemEnvironment() {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    /^(?:PATH|SystemRoot|SystemDrive|WINDIR|COMSPEC|PATHEXT|USERPROFILE|HOMEDRIVE|HOMEPATH|TEMP|TMP|APPDATA|LOCALAPPDATA|PROGRAMDATA|ProgramFiles(?:\(x86\))?|ProgramW6432|CommonProgramFiles(?:\(x86\))?|CommonProgramW6432|DOCKER_CONFIG)$/i.test(key)));
}
async function main() {
  assert.equal(
    process.env.MODERATION_QA,
    'true',
    'MODERATION_QA_OPT_IN_REQUIRED',
  );
  const project = 'sportcenter-moderation-qa-' + process.pid + Date.now();
  const proof = path.join(ROOT, 'test-results', project);
  fs.mkdirSync(proof, { recursive: true, mode: 0o700 });
  let dockerContext;
  const command = (program, args, options = {}) =>
    execFileSync(program, program === 'docker' && dockerContext ? ['--context', dockerContext, ...args] : args, {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...systemEnvironment(), COMPOSE_DISABLE_ENV_FILE: 'true' },
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 30000,
      maxBuffer: 4 * 1024 * 1024,
      ...options,
    });
  dockerContext = command('docker', ['context', 'show']).trim();
  assert.match(dockerContext, /^[a-zA-Z0-9_.-]+$/);
  const context = JSON.parse(command('docker', ['context', 'inspect', dockerContext]));
  assert.equal(context.length, 1);
  assert.ok(['npipe:////./pipe/dockerDesktopLinuxEngine', 'unix:///var/run/docker.sock'].includes(context[0].Endpoints.docker.Host), 'MODERATION_QA_LOCAL_DOCKER_REQUIRED');
  const compose = (args, timeout) =>
    command(
      'docker',
      ['compose', '--project-name', project, '-f', COMPOSE, ...args],
      timeout ? { timeout } : {},
    );
  const config = JSON.parse(compose(['config', '--format', 'json']));
  guard(config);
  command('docker', ['image', 'inspect', PG, '--format', '{{.Id}}']);
  assert.equal(
    compose(['ps', '--all', '--quiet']).trim(),
    '',
    'MODERATION_QA_PROJECT_NOT_EMPTY',
  );
  const jest = path.join(ROOT, 'node_modules/jest/bin/jest.js');
  const discovered = JSON.parse(
    command(
      process.execPath,
      [
        jest,
        '--config',
        'test/jest-moderation.json',
        '--runInBand',
        '--listTests',
        '--json',
      ],
      { env: testEnvironment('15432'), timeout: 20000 },
    ),
  );
  assert.equal(discovered.length, 1);
  assert.equal(
    path.resolve(discovered[0]),
    path.join(ROOT, 'test/moderation.e2e-spec.ts'),
  );
  const before = hashes();
  const report = {
    schemaVersion: 1,
    scope:
      'real-postgres-real-http-moderation-loopback-qa-not-production-not-human-operator',
    baseCommit: command('git', ['rev-parse', 'HEAD']).trim(),
    workingTreeUnderReview: true,
    sourceHashes: before,
    status: 'failed',
    tests: [],
    total: 0,
    noProviderCredentials: true,
    loopbackPortVerified: false,
    internalDatabaseNetwork: false,
    hostProcessLoopbackGuard: true,
    dockerEndpointVerifiedLocal: true,
    migrationReal: true,
    jwtAndRolesReal: true,
    loginIssuanceTested: false,
    fullAppModuleTested: false,
    humanOperatorVerified: false,
    clean: false,
    errorCode: 'NONE',
  };
  let started = false;
  try {
    started = true;
    compose(
      ['up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '60', 'db'],
      75000,
    );
    const id = compose(['ps', '--quiet', 'db']).trim();
    assert.match(id, /^[a-f0-9]{64}$/);
    assert.equal(command('docker', ['network', 'inspect', project + '_isolated', '--format', '{{.Internal}}']).trim(), 'false');
    const ports = JSON.parse(
      command('docker', [
        'inspect',
        id,
        '--format',
        '{{json .NetworkSettings.Ports}}',
      ]),
    );
    assert.deepEqual(Object.keys(ports), ['5432/tcp']);
    assert.equal(ports['5432/tcp'].length, 1);
    const binding = ports['5432/tcp'][0];
    assert.equal(binding.HostIp, '127.0.0.1');
    report.databaseLoopbackPort = Number(binding.HostPort);
    const env = testEnvironment(binding.HostPort);
    report.loopbackPortVerified = true;
    try {
      command(
        process.execPath,
        [
          jest,
          '--config',
          'test/jest-moderation.json',
          '--runInBand',
          '--no-cache',
          '--json',
          '--outputFile=' + path.join(proof, 'jest-private.json'),
        ],
        { env, timeout: 120000 },
      );
    } catch (error) {
      fs.writeFileSync(
        path.join(proof, 'failure-private.txt'),
        String(error.stderr || 'MODERATION_QA_TEST_FAILED'),
        { mode: 0o600 },
      );
    }
    const result = JSON.parse(
      fs.readFileSync(path.join(proof, 'jest-private.json'), 'utf8'),
    );
    report.tests = result.testResults.flatMap((suite) =>
      suite.assertionResults.map((item) => ({
        id: item.title.match(/^M\d\d/)?.[0] || 'UNKNOWN',
        status: item.status,
      })),
    );
    report.total = report.tests.length;
    assert.ok(
      result.success &&
        result.numTotalTests === 23 &&
        result.numPassedTests === result.numTotalTests &&
        result.numPendingTests === 0,
    );
    assert.ok(
      report.tests.every(
        (item) => /^M\d\d$/.test(item.id) && item.status === 'passed',
      ),
    );
    assert.deepEqual(
      hashes(),
      before,
      'MODERATION_QA_SOURCE_CHANGED_DURING_TEST',
    );
    report.status = 'passed';
  } catch (error) {
    report.errorCode = 'MODERATION_QA_ACCEPTANCE_FAILED';
    fs.writeFileSync(
      path.join(proof, 'harness-private.txt'),
      String(error.stack || error) + '\n' + String(error.stderr || ''),
      { mode: 0o600 },
    );
  } finally {
    if (started)
      try {
        const dump = compose(['exec', '-T', 'db', 'pg_dump', '--no-owner', '--no-acl', '-U', 'qa_admin', '-d', 'sportcenter_moderation_qa']);
        fs.writeFileSync(path.join(proof, 'synthetic-final.sql'), dump, { mode: 0o600, flag: 'wx' });
        report.finalDumpSha256 = crypto.createHash('sha256').update(dump).digest('hex');
      } catch { report.finalDumpSha256 = null; }
    if (started)
      try {
        compose(['down', '--remove-orphans', '--timeout', '5']);
        report.clean = compose(['ps', '--all', '--quiet']).trim() === '' &&
          command('docker', ['network', 'ls', '--quiet', '--filter', 'label=com.docker.compose.project=' + project]).trim() === '';
      } catch {
        report.clean = false;
      }
    if (!report.clean) {
      report.status = 'failed';
      report.errorCode = 'MODERATION_QA_CLEANUP_FAILED';
    }
    if (!report.finalDumpSha256) {
      report.status = 'failed';
      report.errorCode = 'MODERATION_QA_BACKUP_FAILED';
    }
    fs.writeFileSync(
      path.join(proof, 'summary.json'),
      JSON.stringify(report, null, 2) + '\n',
      { mode: 0o600 },
    );
  }
  process.stdout.write(
    JSON.stringify({
      status: report.status,
      total: report.total,
      clean: report.clean,
      summary: path.relative(ROOT, path.join(proof, 'summary.json')),
      errorCode: report.errorCode,
    }) + '\n',
  );
  if (report.status !== 'passed') process.exitCode = 1;
}
module.exports = { guard, testEnvironment };
if (require.main === module)
  main().catch((error) => {
    const preparationProof = path.join(ROOT, 'test-results');
    fs.mkdirSync(preparationProof, { recursive: true });
    fs.writeFileSync(path.join(preparationProof, 'preparation-failure-' + process.pid + '-' + Date.now() + '.txt'),
      String(error.stack || error) + '\n' + String(error.stderr || ''), { mode: 0o600 });
    process.stderr.write('MODERATION_QA_PREPARATION_FAILED\n');
    process.exitCode = 1;
  });
