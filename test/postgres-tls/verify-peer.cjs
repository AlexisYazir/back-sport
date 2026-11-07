'use strict';
// Run only inside the isolated, synthetic PostgreSQL TLS fixture.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { DataSource } = require('typeorm');
const {
  postgresConnectionOptions,
} = require('../../dist/src/config/postgres-connection');

async function main() {
  assert.equal(process.env.POSTGRES_TLS_QA, 'true', 'TLS_QA_OPT_IN_REQUIRED');
  const fixture = '/proof';
  const ca = fs.readFileSync(path.join(fixture, 'ca.crt'), 'utf8');
  const wrongCa = fs.readFileSync(path.join(fixture, 'wrong-ca.crt'), 'utf8');
  const checks = [];
  const source = (role, host, certificate, query) =>
    new DataSource({
      type: 'postgres',
      ...postgresConnectionOptions(
        `postgres://qa_${role}:qa-${role}-local@${host}:5432/sportcenter_moderation_qa${query}`,
        2,
        certificate,
      ),
      entities: [],
      synchronize: false,
      installExtensions: false,
      connectTimeoutMS: 3000,
    });
  for (const role of ['admin', 'editor', 'reader', 'backup']) {
    for (const query of ['', '?sslmode=require&channel_binding=require']) {
      const connection = source(role, 'localhost', ca, query);
      try {
        await connection.initialize();
        const rows = await connection.query(
          'SELECT current_user AS role, ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()',
        );
        assert.deepEqual(rows, [{ role: 'qa_' + role, ssl: true }]);
        checks.push({
          role,
          queryPresent: !!query,
          case: 'trusted-peer',
          passed: true,
        });
      } finally {
        if (connection.isInitialized) await connection.destroy();
      }
    }
  }
  for (const [name, host, certificate, expected] of [
    [
      'wrong-ca',
      'localhost',
      wrongCa,
      /UNABLE_TO_VERIFY_LEAF_SIGNATURE|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_GET_ISSUER_CERT_LOCALLY/,
    ],
    ['wrong-hostname', '127.0.0.1', ca, /ERR_TLS_CERT_ALTNAME_INVALID/],
    [
      'no-private-ca',
      'localhost',
      undefined,
      /UNABLE_TO_VERIFY_LEAF_SIGNATURE|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_GET_ISSUER_CERT_LOCALLY/,
    ],
  ]) {
    const connection = source(
      'admin',
      host,
      certificate,
      '?sslmode=require&channel_binding=require',
    );
    let rejected;
    try {
      await connection.initialize();
    } catch (error) {
      rejected = error;
    } finally {
      if (connection.isInitialized) await connection.destroy();
    }
    assert.ok(rejected, name + ' must reject the peer');
    assert.match(String(rejected.code), expected);
    checks.push({ case: name, passed: true, errorCode: rejected.code });
  }
  console.log(JSON.stringify({ status: 'passed', checks }));
}
main().catch((error) => {
  // Do not print driver errors or connection objects containing credentials.
  console.error('POSTGRES_TLS_QA_FAILED', error.code || error.name);
  process.exitCode = 1;
});
