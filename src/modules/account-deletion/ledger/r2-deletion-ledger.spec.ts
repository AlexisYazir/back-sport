import {
  GetObjectCommand,
  GetObjectCommandOutput,
  PutObjectCommand,
} from '@aws-sdk/client-s3';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { DeletionIntent, DeletionRetention } from './deletion-ledger';
import {
  R2DeletionClient,
  R2DeletionLedger,
  R2DeletionLedgerOptions,
} from './r2-deletion-ledger';

function providerError(code: number): Error {
  return Object.assign(new Error('private-provider-detail-must-not-leak'), {
    $metadata: { httpStatusCode: code },
  });
}

class MemoryR2 implements R2DeletionClient {
  readonly objects = new Map<string, { raw: string; etag: string }>();
  readonly puts: PutObjectCommand['input'][] = [];
  conflicts = 0;
  conflictEverySnapshot = false;
  failNext:
    | { key: 'manifest.json' | 'snapshot.json'; after: boolean }
    | undefined;
  omitEtag = false;
  private revision = 0;

  send(
    command: GetObjectCommand,
  ): Promise<Pick<GetObjectCommandOutput, 'Body' | 'ETag' | 'ContentLength'>>;
  send(command: PutObjectCommand): Promise<unknown>;
  async send(command: GetObjectCommand | PutObjectCommand): Promise<any> {
    await Promise.resolve();
    const key = `${command.input.Bucket}/${command.input.Key}`;
    if (command instanceof GetObjectCommand) {
      const stored = this.objects.get(key);
      if (!stored) throw providerError(404);
      return {
        Body: Readable.from([Buffer.from(stored.raw)]),
        ETag: this.omitEtag ? undefined : stored.etag,
        ContentLength: Buffer.byteLength(stored.raw),
      };
    }
    this.puts.push({ ...command.input });
    const existing = this.objects.get(key);
    if (
      (command.input.IfNoneMatch === '*' && existing) ||
      (command.input.IfMatch !== undefined &&
        command.input.IfMatch !== existing?.etag) ||
      (this.conflictEverySnapshot && key.endsWith('/snapshot.json'))
    ) {
      this.conflicts++;
      throw providerError(this.conflicts % 2 ? 412 : 409);
    }
    const shouldFail =
      this.failNext && key.endsWith('/' + this.failNext.key)
        ? this.failNext
        : undefined;
    if (shouldFail) this.failNext = undefined;
    if (shouldFail && !shouldFail.after) throw providerError(503);
    const raw = Buffer.from(command.input.Body as Uint8Array).toString('utf8');
    const etag = `"revision-${++this.revision}"`;
    this.objects.set(key, { raw, etag });
    if (shouldFail?.after) throw providerError(503);
    return { ETag: etag };
  }
  mutate(key: string, change: (raw: string) => string): void {
    const previous = this.objects.get(key)!;
    this.objects.set(key, {
      raw: change(previous.raw),
      etag: `"changed-${++this.revision}"`,
    });
  }
}

function fixture() {
  const client = new MemoryR2();
  const options: R2DeletionLedgerOptions = {
    client,
    bucket: 'qa-private-ledger',
    prefix: `_account-deletion/v1/${createHash('sha256').update('synthetic-database').digest('hex')}/`,
    wrappingSecret: randomBytes(48).toString('base64url'),
    databaseHasHistory: false,
  };
  const intent: DeletionIntent = {
    operationId: randomUUID(),
    accountId: randomUUID(),
    legacyUserId: 18,
    legacyFingerprint: randomBytes(32).toString('hex'),
  };
  const retention: DeletionRetention = {
    until: '2030-11-08T10:00:00.000Z',
    basisHash: randomBytes(32).toString('hex'),
    categories: ['payments', 'orders'],
  };
  const key = (name: string) => `${options.bucket}/${options.prefix}${name}`;
  return { client, options, intent, retention, key };
}

describe('R2DeletionLedger', () => {
  test('provisions independent random secrets once, wrapped with a purpose-separated key', async () => {
    const { client, options, key } = fixture();
    const opened = await R2DeletionLedger.open(options);
    expect(opened.operationSecret).toMatch(/^[a-f\d]{64}$/);
    expect(opened.ledgerSecret).toMatch(/^[a-f\d]{64}$/);
    expect(
      new Set([
        options.wrappingSecret,
        opened.operationSecret,
        opened.ledgerSecret,
      ]).size,
    ).toBe(3);
    expect(client.puts).toHaveLength(3);
    for (const put of client.puts) {
      expect(put.CacheControl).toBe('no-store');
      expect(put.ContentType).toBe('application/json');
      expect(Boolean(put.IfMatch) !== Boolean(put.IfNoneMatch)).toBe(true);
    }
    const manifestRaw = client.objects.get(key('manifest.json'))!.raw;
    expect(manifestRaw).not.toContain(options.wrappingSecret);
    expect(manifestRaw).not.toContain(opened.operationSecret);
    expect(manifestRaw).not.toContain(opened.ledgerSecret);
    expect(
      (JSON.parse(manifestRaw) as { body: { phase: string } }).body.phase,
    ).toBe('active');
    const reopened = await R2DeletionLedger.open({
      ...options,
      expectedLedgerId: opened.ledgerId,
    });
    expect(reopened.ledgerId).toBe(opened.ledgerId);
    expect(reopened.operationSecret).toBe(opened.operationSecret);
    expect(reopened.ledgerSecret).toBe(opened.ledgerSecret);
    expect(client.puts).toHaveLength(3);
    expect(await reopened.ledger.verifyAndRead()).toMatchObject({
      sequence: 0,
      intents: [],
    });
  });

  test('concurrent initializers converge on exactly the same persistent identity and keys', async () => {
    const { options, client } = fixture();
    const [one, two] = await Promise.all([
      R2DeletionLedger.open(options),
      R2DeletionLedger.open(options),
    ]);
    expect(one.ledgerId).toBe(two.ledgerId);
    expect(one.operationSecret).toBe(two.operationSecret);
    expect(one.ledgerSecret).toBe(two.ledgerSecret);
    expect(client.objects.size).toBe(2);
    expect(client.conflicts).toBeGreaterThan(0);
  });

  test('merges concurrent writes by two independent instances without losing 25 intents or completions', async () => {
    const { options, client, intent } = fixture();
    const one = await R2DeletionLedger.open(options),
      two = await R2DeletionLedger.open(options);
    const intents = Array.from({ length: 25 }, (_, index) => ({
      ...intent,
      operationId: randomUUID(),
      accountId: randomUUID(),
      legacyUserId: index + 1,
    }));
    await Promise.all(
      intents.map((record, index) =>
        (index % 2 ? one : two).ledger.recordIntent(record),
      ),
    );
    await Promise.all(
      intents.map((record, index) =>
        (index % 2 ? two : one).ledger.markCompleted(record.operationId),
      ),
    );
    const snapshot = await one.ledger.verifyAndRead();
    expect(snapshot.sequence).toBe(50);
    expect(snapshot.intents).toHaveLength(25);
    expect(snapshot.intents.every((record) => record.completed)).toBe(true);
    expect(
      new Set(snapshot.intents.map((record) => record.operationId)),
    ).toEqual(new Set(intents.map((record) => record.operationId)));
    expect(client.conflicts).toBeGreaterThan(0);
    expect(await two.ledger.verifyAndRead()).toEqual(snapshot);
  });

  test('rejects conflicting identities sharing an operation while preserving the winner', async () => {
    const { options, intent } = fixture();
    const one = await R2DeletionLedger.open(options),
      two = await R2DeletionLedger.open(options);
    const results = await Promise.allSettled([
      one.ledger.recordIntent(intent),
      two.ledger.recordIntent({ ...intent, accountId: randomUUID() }),
    ]);
    expect(
      results.filter((record) => record.status === 'fulfilled'),
    ).toHaveLength(1);
    expect(
      results.find((record) => record.status === 'rejected'),
    ).toMatchObject({ reason: { code: 'CONFLICT' } });
    expect((await one.ledger.verifyAndRead()).intents).toHaveLength(1);
  });

  test('retention and completion are idempotent and cannot reset the durable deadline', async () => {
    const { options, intent, retention } = fixture();
    const { ledger } = await R2DeletionLedger.open(options);
    await ledger.recordIntent(intent);
    await ledger.recordIntent(intent);
    await ledger.recordRetention(intent.operationId, retention);
    await ledger.recordRetention(intent.operationId, {
      ...retention,
      categories: ['orders', 'payments'],
    });
    await expect(
      ledger.recordRetention(intent.operationId, {
        ...retention,
        until: '2031-11-08T10:00:00.000Z',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await ledger.markCompleted(intent.operationId);
    await ledger.markCompleted(intent.operationId);
    const reopened = await R2DeletionLedger.open({
      ...options,
      databaseHasHistory: true,
    });
    expect(await reopened.ledger.verifyAndRead()).toMatchObject({
      sequence: 3,
      intents: [
        {
          ...intent,
          completed: true,
          retention: { ...retention, categories: ['orders', 'payments'] },
        },
      ],
    });
  });

  test.each(['manifest.json', 'snapshot.json'])(
    'never recreates a missing active %s, including after a pre-install database restore',
    async (name) => {
      const { options, client, key, intent } = fixture();
      const { ledger } = await R2DeletionLedger.open(options);
      await ledger.recordIntent(intent);
      client.objects.delete(key(name));
      const writes = client.puts.length;
      await expect(R2DeletionLedger.open(options)).rejects.toMatchObject({
        code: 'INTEGRITY_FAILURE',
      });
      await expect(ledger.verifyAndRead()).rejects.toMatchObject({
        code: 'INTEGRITY_FAILURE',
      });
      expect(client.puts).toHaveLength(writes);
    },
  );

  test('missing both objects cannot initialize when database history or a ledger binding exists', async () => {
    const { options, client } = fixture();
    await expect(
      R2DeletionLedger.open({ ...options, databaseHasHistory: true }),
    ).rejects.toMatchObject({ code: 'INTEGRITY_FAILURE' });
    await expect(
      R2DeletionLedger.open({ ...options, expectedLedgerId: randomUUID() }),
    ).rejects.toMatchObject({ code: 'INTEGRITY_FAILURE' });
    expect(client.puts).toHaveLength(0);
  });

  test('database-only restore reuses all R2 history and the original retention deadline', async () => {
    const { options, intent, retention } = fixture();
    const initial = await R2DeletionLedger.open(options);
    await initial.ledger.recordIntent(intent);
    await initial.ledger.recordRetention(intent.operationId, retention);
    await initial.ledger.markCompleted(intent.operationId);
    const restored = await R2DeletionLedger.open({
      ...options,
      databaseHasHistory: false,
    });
    expect(restored.ledgerId).toBe(initial.ledgerId);
    expect(await restored.ledger.verifyAndRead()).toEqual(
      await initial.ledger.verifyAndRead(),
    );
  });

  test('wrong root, copied namespace or conflicting expected identity cannot re-key history', async () => {
    const { options, client, key } = fixture();
    await R2DeletionLedger.open(options);
    const writes = client.puts.length;
    await expect(
      R2DeletionLedger.open({
        ...options,
        wrappingSecret: randomBytes(48).toString('hex'),
      }),
    ).rejects.toMatchObject({ code: 'INTEGRITY_FAILURE' });
    await expect(
      R2DeletionLedger.open({ ...options, expectedLedgerId: randomUUID() }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const copied = {
      ...options,
      prefix: `_account-deletion/v1/${'f'.repeat(64)}/`,
    };
    client.objects.set(
      `${options.bucket}/${copied.prefix}manifest.json`,
      client.objects.get(key('manifest.json'))!,
    );
    client.objects.set(
      `${options.bucket}/${copied.prefix}snapshot.json`,
      client.objects.get(key('snapshot.json'))!,
    );
    await expect(R2DeletionLedger.open(copied)).rejects.toMatchObject({
      code: 'INTEGRITY_FAILURE',
    });
    expect(client.puts).toHaveLength(writes);
  });

  test.each(['manifest.json', 'snapshot.json'])(
    'rejects altered %s without exposing provider or key material',
    async (name) => {
      const { options, client, key } = fixture();
      const initial = await R2DeletionLedger.open(options);
      client.mutate(key(name), (raw) =>
        raw.replace(/"mac":"[a-f\d]{64}"/, `"mac":"${'0'.repeat(64)}"`),
      );
      await expect(R2DeletionLedger.open(options)).rejects.toMatchObject({
        message: 'ACCOUNT_DELETION_LEDGER_INTEGRITY_FAILURE',
      });
      await expect(initial.ledger.verifyAndRead()).rejects.not.toThrow(
        options.wrappingSecret,
      );
    },
  );

  test('whole-snapshot authentication rejects truncation even with intact entry signatures', async () => {
    const { options, client, key, intent } = fixture();
    const { ledger } = await R2DeletionLedger.open(options);
    await ledger.recordIntent(intent);
    client.mutate(key('snapshot.json'), (raw) => {
      const value = JSON.parse(raw) as { entries: unknown[] };
      value.entries = value.entries.slice(0, 1);
      return JSON.stringify(value);
    });
    await expect(R2DeletionLedger.open(options)).rejects.toMatchObject({
      code: 'INTEGRITY_FAILURE',
    });
  });

  test('rejects injected private fields and duplicate JSON keys before replay', async () => {
    const { options, client, key } = fixture();
    await R2DeletionLedger.open(options);
    client.mutate(key('snapshot.json'), (raw) =>
      raw.replace('{"version":1,', '{"version":1,"version":1,'),
    );
    await expect(R2DeletionLedger.open(options)).rejects.toMatchObject({
      code: 'INTEGRITY_FAILURE',
    });
  });

  test('resumes an interrupted first provisioning but cannot do so over database history', async () => {
    const { options, client, key } = fixture();
    client.failNext = { key: 'snapshot.json', after: false };
    await expect(R2DeletionLedger.open(options)).rejects.toMatchObject({
      code: 'UNAVAILABLE',
    });
    expect(
      (
        JSON.parse(client.objects.get(key('manifest.json'))!.raw) as {
          body: { phase: string };
        }
      ).body.phase,
    ).toBe('provisioning');
    const writes = client.puts.length;
    await expect(
      R2DeletionLedger.open({ ...options, databaseHasHistory: true }),
    ).rejects.toMatchObject({ code: 'INTEGRITY_FAILURE' });
    expect(client.puts).toHaveLength(writes);
    const recovered = await R2DeletionLedger.open(options);
    expect(await recovered.ledger.verifyAndRead()).toMatchObject({
      sequence: 0,
    });
    expect(
      (
        JSON.parse(client.objects.get(key('manifest.json'))!.raw) as {
          body: { phase: string };
        }
      ).body.phase,
    ).toBe('active');
  });

  test.each(['manifest.json', 'snapshot.json'] as const)(
    'reconciles ambiguous committed %s during provisioning',
    async (name) => {
      const { options, client } = fixture();
      client.failNext = { key: name, after: true };
      const { ledger } = await R2DeletionLedger.open(options);
      expect(await ledger.verifyAndRead()).toMatchObject({
        sequence: 0,
        intents: [],
      });
    },
  );

  test('reconciles a committed timeout once and never blindly retries an uncommitted timeout', async () => {
    const { options, client, intent } = fixture();
    const { ledger } = await R2DeletionLedger.open(options);
    client.failNext = { key: 'snapshot.json', after: true };
    await ledger.recordIntent(intent);
    expect((await ledger.verifyAndRead()).sequence).toBe(1);
    client.failNext = { key: 'snapshot.json', after: false };
    const writes = client.puts.length;
    await expect(
      ledger.markCompleted(intent.operationId),
    ).rejects.toMatchObject({ message: 'ACCOUNT_DELETION_LEDGER_UNAVAILABLE' });
    expect(client.puts).toHaveLength(writes + 1);
    expect((await ledger.verifyAndRead()).intents[0].completed).toBe(false);
    await ledger.markCompleted(intent.operationId);
    expect((await ledger.verifyAndRead()).sequence).toBe(2);
  });

  test('bounds conditional conflicts and leaves history unchanged on exhausted contention', async () => {
    const { options, client, intent } = fixture();
    const { ledger } = await R2DeletionLedger.open(options);
    client.conflictEverySnapshot = true;
    const writes = client.puts.length;
    await expect(ledger.recordIntent(intent)).rejects.toMatchObject({
      code: 'UNAVAILABLE',
    });
    expect(client.puts.length - writes).toBe(32);
    expect(await ledger.verifyAndRead()).toMatchObject({
      sequence: 0,
      intents: [],
    });
  });

  test('rejects a signed older snapshot after observing a later sequence in the same instance', async () => {
    const { options, client, intent, key } = fixture();
    const { ledger } = await R2DeletionLedger.open(options);
    const older = client.objects.get(key('snapshot.json'))!;
    await ledger.recordIntent(intent);
    client.objects.set(key('snapshot.json'), older);
    await expect(ledger.verifyAndRead()).rejects.toMatchObject({
      code: 'INTEGRITY_FAILURE',
    });
  });

  test('invalid records are rejected before writes and cannot add PII fields to the journal', async () => {
    const { options, client, intent, retention } = fixture();
    const { ledger } = await R2DeletionLedger.open(options);
    const writes = client.puts.length;
    await expect(
      ledger.recordIntent({
        ...intent,
        email: 'synthetic@example.invalid',
      } as DeletionIntent),
    ).rejects.toMatchObject({ code: 'INVALID_RECORD' });
    await expect(
      ledger.recordRetention(intent.operationId, {
        ...retention,
        categories: ['invalid' as 'orders'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_RECORD' });
    await expect(ledger.markCompleted('invalid')).rejects.toMatchObject({
      code: 'INVALID_RECORD',
    });
    expect(client.puts).toHaveLength(writes);
  });

  test('never accepts missing ETags or short root secrets as automatic configuration', async () => {
    const { options, client } = fixture();
    await expect(
      R2DeletionLedger.open({ ...options, wrappingSecret: 'short' }),
    ).rejects.toMatchObject({ code: 'INVALID_CONFIGURATION' });
    await R2DeletionLedger.open(options);
    client.omitEtag = true;
    await expect(R2DeletionLedger.open(options)).rejects.toMatchObject({
      code: 'INTEGRITY_FAILURE',
    });
  });
});
