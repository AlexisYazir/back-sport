import { randomBytes, randomUUID } from 'node:crypto';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DeletionIntent,
  DeletionLedgerError,
  DeletionRetention,
} from './deletion-ledger';
import {
  FileDeletionLedger,
  FileDeletionLedgerOptions,
} from './file-deletion-ledger';
import { PrivateStorageVerifier } from './private-storage';

// These fixtures exercise file durability/integrity, not the host's DACL.
// The production constructor defaults to the native private-storage verifier.
const fixturePrivacy: PrivateStorageVerifier = async (path, kind) => {
  const stat = await lstat(path);
  if (
    stat.isSymbolicLink() ||
    (kind === 'file' ? !stat.isFile() || stat.nlink !== 1 : !stat.isDirectory())
  ) {
    throw new DeletionLedgerError('UNSAFE_STORAGE');
  }
};

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'sportcenter-deletion-ledger-'));
  const directory = join(root, 'private-ledger');
  await mkdir(directory, { mode: 0o700 });
  const options: FileDeletionLedgerOptions = {
    directory,
    repositoryRoot: join(root, 'repository'),
    hmacKey: randomBytes(32),
    verifyPrivateStorage: fixturePrivacy,
  };
  const ledger = new FileDeletionLedger(options);
  const intent: DeletionIntent = {
    operationId: randomUUID(),
    accountId: randomUUID(),
    legacyUserId: 18,
    legacyFingerprint: randomBytes(32).toString('hex'),
  };
  return { directory, options, ledger, intent };
}

describe('FileDeletionLedger', () => {
  test('requires an absolute independent directory and dedicated strong key', async () => {
    const { options } = await fixture();
    expect(
      () => new FileDeletionLedger({ ...options, directory: 'relative' }),
    ).toThrow('INVALID_CONFIGURATION');
    expect(
      () => new FileDeletionLedger({ ...options, repositoryRoot: 'relative' }),
    ).toThrow('INVALID_CONFIGURATION');
    expect(
      () =>
        new FileDeletionLedger({
          ...options,
          directory: options.repositoryRoot,
        }),
    ).toThrow('INVALID_CONFIGURATION');
    expect(
      () =>
        new FileDeletionLedger({
          ...options,
          directory: join(options.repositoryRoot, 'backups'),
        }),
    ).toThrow('INVALID_CONFIGURATION');
    expect(
      () => new FileDeletionLedger({ ...options, hmacKey: Buffer.alloc(31) }),
    ).toThrow('INVALID_CONFIGURATION');
  });

  test('does not create or silently initialize a missing ledger at startup', async () => {
    const { ledger, directory } = await fixture();
    await expect(ledger.verifyAndRead()).rejects.toThrow('UNAVAILABLE');
    await expect(
      readFile(join(directory, 'deletions.jsonl')),
    ).rejects.toMatchObject({ code: 'ENOENT' });
  });

  test('explicit provisioning is durable, readable by another instance and never overwrites', async () => {
    const { ledger, options, directory } = await fixture();
    await ledger.initializeNew();
    const bytes = await readFile(join(directory, 'deletions.jsonl'));
    const second = new FileDeletionLedger(options);
    await expect(second.verifyAndRead()).resolves.toMatchObject({
      sequence: 0,
      intents: [],
    });
    await expect(ledger.initializeNew()).rejects.toThrow('CONFLICT');
    expect(await readFile(join(directory, 'deletions.jsonl'))).toEqual(bytes);
  });

  test('appends monotonic intent/completion events and persists idempotency', async () => {
    const { ledger, options, intent } = await fixture();
    await ledger.initializeNew();
    await ledger.recordIntent(intent);
    const first = await ledger.verifyAndRead();
    expect(first.sequence).toBe(1);
    expect(first.intents).toEqual([{ ...intent, completed: false }]);
    await ledger.recordIntent(intent);
    expect((await ledger.verifyAndRead()).digest).toBe(first.digest);
    await ledger.markCompleted(intent.operationId);
    const second = new FileDeletionLedger(options);
    await second.markCompleted(intent.operationId);
    await second.recordIntent(intent);
    await expect(second.verifyAndRead()).resolves.toMatchObject({
      sequence: 2,
      intents: [{ ...intent, completed: true }],
    });
  });

  test('rejects another repository and an orphaned preexisting head before creating a log', async () => {
    const { ledger, directory } = await fixture();
    await mkdir(join(directory, '.git'));
    await expect(ledger.initializeNew()).rejects.toThrow(
      'INVALID_CONFIGURATION',
    );
    const separate = await fixture();
    await writeFile(
      join(separate.directory, 'deletions.head.json'),
      'PRESERVE_ORPHANED_CHECKPOINT',
    );
    await expect(separate.ledger.initializeNew()).rejects.toThrow('CONFLICT');
    await expect(
      readFile(join(separate.directory, 'deletions.jsonl')),
    ).rejects.toMatchObject({ code: 'ENOENT' });
    expect(
      await readFile(join(separate.directory, 'deletions.head.json'), 'utf8'),
    ).toBe('PRESERVE_ORPHANED_CHECKPOINT');
  });

  test('rejects operation ID reuse for a different account identity', async () => {
    const { ledger, intent } = await fixture();
    await ledger.initializeNew();
    await ledger.recordIntent(intent);
    await expect(
      ledger.recordIntent({ ...intent, accountId: randomUUID() }),
    ).rejects.toThrow('CONFLICT');
    await expect(ledger.markCompleted(randomUUID())).rejects.toThrow(
      'CONFLICT',
    );
  });

  test('retention metadata is durable and preserves its original deadline across restarts and retries', async () => {
    const { ledger, options, intent } = await fixture();
    const retention: DeletionRetention = {
      until: '2030-01-02T03:04:05.000Z',
      basisHash: randomBytes(32).toString('hex'),
      categories: ['payments', 'orders'],
    };
    await ledger.initializeNew();
    await ledger.recordIntent(intent);
    await ledger.recordRetention(intent.operationId, retention);
    const original = await ledger.verifyAndRead();
    expect(original.sequence).toBe(2);
    expect(original.intents[0].retention).toEqual({
      ...retention,
      categories: ['orders', 'payments'],
    });
    const restarted = new FileDeletionLedger(options);
    await restarted.recordRetention(intent.operationId, {
      ...retention,
      categories: ['orders', 'payments'],
    });
    expect((await restarted.verifyAndRead()).digest).toBe(original.digest);
    await restarted.markCompleted(intent.operationId);
    await restarted.recordRetention(intent.operationId, retention);
    expect((await restarted.verifyAndRead()).intents[0]).toMatchObject({
      completed: true,
      retention: { until: retention.until },
    });
  });

  test('retention cannot be replaced, extended or invented after completion', async () => {
    const { ledger, intent } = await fixture();
    const retention: DeletionRetention = {
      until: '2030-01-02T03:04:05.000Z',
      basisHash: randomBytes(32).toString('hex'),
      categories: ['orders'],
    };
    await ledger.initializeNew();
    await ledger.recordIntent(intent);
    await expect(
      ledger.recordRetention(randomUUID(), retention),
    ).rejects.toThrow('CONFLICT');
    await ledger.recordRetention(intent.operationId, retention);
    await expect(
      ledger.recordRetention(intent.operationId, {
        ...retention,
        until: '2040-01-02T03:04:05.000Z',
      }),
    ).rejects.toThrow('CONFLICT');
    await expect(
      ledger.recordRetention(intent.operationId, {
        ...retention,
        categories: ['orders', 'returns'],
      }),
    ).rejects.toThrow('CONFLICT');
    const second = { ...intent, operationId: randomUUID() };
    await ledger.recordIntent(second);
    await ledger.markCompleted(second.operationId);
    await expect(
      ledger.recordRetention(second.operationId, retention),
    ).rejects.toThrow('CONFLICT');
  });

  test('retention rejects personal text, unreviewed categories, invalid dates and unknown fields', async () => {
    const { ledger, intent, directory } = await fixture();
    const retention: DeletionRetention = {
      until: '2030-01-02T03:04:05.000Z',
      basisHash: randomBytes(32).toString('hex'),
      categories: ['orders'],
    };
    await ledger.initializeNew();
    await ledger.recordIntent(intent);
    for (const invalid of [
      { ...retention, basis: 'CANARY_PRIVATE_LEGAL_TEXT' },
      { ...retention, basisHash: 'CANARY_PERSONAL_DATA' },
      { ...retention, until: 'not-a-date' },
      { ...retention, categories: ['moderation_records'] },
      { ...retention, categories: ['orders', 'orders'] },
      { ...retention, categories: [] },
    ])
      await expect(
        ledger.recordRetention(
          intent.operationId,
          invalid as DeletionRetention,
        ),
      ).rejects.toThrow('INVALID_RECORD');
    await ledger.recordRetention(intent.operationId, retention);
    expect(
      await readFile(join(directory, 'deletions.jsonl'), 'utf8'),
    ).not.toMatch(/CANARY|basis"|email|password|token/i);
  });

  test('retention deadline tampering breaks ledger integrity', async () => {
    const { ledger, intent, directory } = await fixture();
    const retention: DeletionRetention = {
      until: '2030-01-02T03:04:05.000Z',
      basisHash: randomBytes(32).toString('hex'),
      categories: ['returns'],
    };
    await ledger.initializeNew();
    await ledger.recordIntent(intent);
    await ledger.recordRetention(intent.operationId, retention);
    const path = join(directory, 'deletions.jsonl');
    await writeFile(
      path,
      (await readFile(path, 'utf8')).replace(
        retention.until,
        '2040-01-02T03:04:05.000Z',
      ),
    );
    await expect(ledger.verifyAndRead()).rejects.toThrow('INTEGRITY_FAILURE');
  });

  test('rejects unknown fields and personal or credential payloads', async () => {
    const { ledger, intent, directory } = await fixture();
    await ledger.initializeNew();
    await expect(
      ledger.recordIntent({
        ...intent,
        email: 'PRIVATE_EMAIL_CANARY',
      } as DeletionIntent),
    ).rejects.toThrow('INVALID_RECORD');
    await expect(
      ledger.recordIntent({ ...intent, legacyFingerprint: 'OTP_CANARY' }),
    ).rejects.toThrow('INVALID_RECORD');
    await ledger.recordIntent(intent);
    const log = await readFile(join(directory, 'deletions.jsonl'), 'utf8');
    expect(log).not.toMatch(
      /PRIVATE_EMAIL_CANARY|OTP_CANARY|email|password|token/i,
    );
  });

  test('normalizes UUID casing without duplicating an operation', async () => {
    const { ledger, intent } = await fixture();
    await ledger.initializeNew();
    await ledger.recordIntent({
      ...intent,
      accountId: intent.accountId.toUpperCase(),
      operationId: intent.operationId.toUpperCase(),
    });
    await ledger.recordIntent(intent);
    await expect(ledger.verifyAndRead()).resolves.toMatchObject({
      sequence: 1,
    });
  });

  test('rejects changed content even when it is valid JSON', async () => {
    const { ledger, intent, directory } = await fixture();
    await ledger.initializeNew();
    await ledger.recordIntent(intent);
    const path = join(directory, 'deletions.jsonl');
    const log = await readFile(path, 'utf8');
    await writeFile(
      path,
      log.replace(`"legacyUserId":${intent.legacyUserId}`, '"legacyUserId":99'),
    );
    await expect(ledger.verifyAndRead()).rejects.toThrow('INTEGRITY_FAILURE');
  });

  test('rejects reordered lines, a partial final write and trailing garbage', async () => {
    const { ledger, intent, directory } = await fixture();
    await ledger.initializeNew();
    await ledger.recordIntent(intent);
    await ledger.markCompleted(intent.operationId);
    const path = join(directory, 'deletions.jsonl');
    const log = await readFile(path, 'utf8');
    const lines = log.trimEnd().split('\n');
    await writeFile(path, [lines[0], lines[2], lines[1]].join('\n') + '\n');
    await expect(ledger.verifyAndRead()).rejects.toThrow('INTEGRITY_FAILURE');
    await writeFile(path, log.slice(0, -4));
    await expect(ledger.verifyAndRead()).rejects.toThrow('INTEGRITY_FAILURE');
    await writeFile(path, log + '{}\n');
    await expect(ledger.verifyAndRead()).rejects.toThrow('INTEGRITY_FAILURE');
  });

  test('detects tail truncation using the independently signed head', async () => {
    const { ledger, intent, directory } = await fixture();
    await ledger.initializeNew();
    const path = join(directory, 'deletions.jsonl');
    const original = await readFile(path, 'utf8');
    await ledger.recordIntent(intent);
    await writeFile(path, original);
    await expect(ledger.verifyAndRead()).rejects.toThrow('INTEGRITY_FAILURE');
  });

  test('fails closed after log append without matching checkpoint, without repairing it', async () => {
    const { ledger, intent, directory } = await fixture();
    await ledger.initializeNew();
    const headPath = join(directory, 'deletions.head.json');
    const oldHead = await readFile(headPath, 'utf8');
    await ledger.recordIntent(intent);
    await writeFile(headPath, oldHead);
    await expect(ledger.verifyAndRead()).rejects.toThrow('INTEGRITY_FAILURE');
    expect(await readFile(headPath, 'utf8')).toBe(oldHead);
  });

  test('rejects changed, missing or mismatched-key head/log', async () => {
    const { ledger, options, directory } = await fixture();
    await ledger.initializeNew();
    const otherKey = new FileDeletionLedger({
      ...options,
      hmacKey: randomBytes(32),
    });
    await expect(otherKey.verifyAndRead()).rejects.toThrow('INTEGRITY_FAILURE');
    const headPath = join(directory, 'deletions.head.json');
    const original = await readFile(headPath, 'utf8');
    await writeFile(headPath, original.replace('"sequence":0', '"sequence":1'));
    await expect(ledger.verifyAndRead()).rejects.toThrow('INTEGRITY_FAILURE');
    await unlink(headPath);
    await expect(ledger.verifyAndRead()).rejects.toThrow('UNAVAILABLE');
  });

  test('uses an exclusive process lock and never takes over a stale lock', async () => {
    const { ledger, options, directory, intent } = await fixture();
    await ledger.initializeNew();
    const lock = join(directory, 'deletion.lock');
    await writeFile(lock, 'OTHER_PROCESS_OR_STALE_LOCK', {
      flag: 'wx',
      mode: 0o600,
    });
    const other = new FileDeletionLedger(options);
    await expect(other.recordIntent(intent)).rejects.toThrow('LOCKED');
    await expect(ledger.verifyAndRead()).rejects.toThrow('LOCKED');
    expect(await readFile(lock, 'utf8')).toBe('OTHER_PROCESS_OR_STALE_LOCK');
    await unlink(lock);
    await other.recordIntent(intent);
    expect((await ledger.verifyAndRead()).intents).toHaveLength(1);
  });

  test('rejects unsafe storage permissions and hides provider error details', async () => {
    const { options } = await fixture();
    const unsafe = new FileDeletionLedger({
      ...options,
      verifyPrivateStorage: () =>
        Promise.reject(new DeletionLedgerError('UNSAFE_STORAGE')),
    });
    await expect(unsafe.initializeNew()).rejects.toThrow('UNSAFE_STORAGE');
    const inaccessible = new FileDeletionLedger({
      ...options,
      verifyPrivateStorage: () =>
        Promise.reject(new Error('CANARY_PRIVATE_PATH_OR_SECRET')),
    });
    await expect(inaccessible.verifyAndRead()).rejects.toThrow(
      'ACCOUNT_DELETION_LEDGER_UNAVAILABLE',
    );
    await expect(inaccessible.verifyAndRead()).rejects.not.toThrow('CANARY');
  });
});
