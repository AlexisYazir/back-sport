import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import {
  lstat,
  open,
  readFile,
  realpath,
  rename,
  unlink,
} from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import {
  DeletionIntent,
  DeletionLedger,
  DeletionLedgerError,
  DeletionLedgerSnapshot,
  DeletionRetention,
  RecordedDeletionIntent,
} from './deletion-ledger';
import {
  assertPrivateStorage,
  PrivateStorageVerifier,
} from './private-storage';

const ZERO = '0'.repeat(64);
const HEX = /^[0-9a-f]{64}$/;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_BYTES = 64 * 1024 * 1024;

interface EntryBody {
  version: 1;
  ledgerId: string;
  sequence: number;
  previousDigest: string;
  type: 'genesis' | 'intent' | 'retention' | 'completed';
  operationId?: string;
  accountId?: string;
  legacyUserId?: number;
  legacyFingerprint?: string;
  retention?: DeletionRetention;
}
interface Entry {
  body: EntryBody;
  mac: string;
}
interface HeadBody {
  version: 1;
  ledgerId: string;
  sequence: number;
  digest: string;
}
interface Head {
  body: HeadBody;
  mac: string;
}
export interface FileDeletionLedgerOptions {
  /** Pre-provisioned, private, persistent directory OUTSIDE the repository. */
  directory: string;
  repositoryRoot: string;
  /** Dedicated random key, at least 32 bytes. Never reuse a JWT secret. */
  hmacKey: Buffer;
  /** OS verifier injection is intended for equivalent platform adapters/tests. */
  verifyPrivateStorage?: PrivateStorageVerifier;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function keys(value: Record<string, unknown>, expected: string[]): boolean {
  return Object.keys(value).sort().join('|') === expected.sort().join('|');
}
function validIntent(value: unknown): value is DeletionIntent {
  return (
    object(value) &&
    keys(value, [
      'operationId',
      'accountId',
      'legacyUserId',
      'legacyFingerprint',
    ]) &&
    typeof value.operationId === 'string' &&
    UUID.test(value.operationId) &&
    typeof value.accountId === 'string' &&
    UUID.test(value.accountId) &&
    Number.isSafeInteger(value.legacyUserId) &&
    Number(value.legacyUserId) > 0 &&
    typeof value.legacyFingerprint === 'string' &&
    HEX.test(value.legacyFingerprint)
  );
}
function normalized(intent: DeletionIntent): DeletionIntent {
  return {
    operationId: intent.operationId.toLowerCase(),
    accountId: intent.accountId.toLowerCase(),
    legacyUserId: intent.legacyUserId,
    legacyFingerprint: intent.legacyFingerprint,
  };
}

function validRetention(value: unknown): value is DeletionRetention {
  return (
    object(value) &&
    keys(value, ['until', 'basisHash', 'categories']) &&
    typeof value.until === 'string' &&
    Number.isFinite(Date.parse(value.until)) &&
    new Date(value.until).toISOString() === value.until &&
    typeof value.basisHash === 'string' &&
    HEX.test(value.basisHash) &&
    Array.isArray(value.categories) &&
    value.categories.length > 0 &&
    value.categories.every(
      (category) =>
        typeof category === 'string' &&
        ['orders', 'payments', 'returns'].includes(category),
    ) &&
    new Set(value.categories).size === value.categories.length
  );
}

function normalizeRetention(value: DeletionRetention): DeletionRetention {
  return {
    until: value.until,
    basisHash: value.basisHash,
    categories: [...value.categories].sort(),
  };
}

/**
 * Every acknowledged append is fsynced and bound to a separately signed head.
 * This detects edits, reorder and tail truncation while the head is preserved.
 * Rollback of BOTH files requires an external immutable/versioned checkpoint;
 * a local filesystem alone cannot prove that such rollback has not happened.
 * Neither file may be included in a database backup or recreated at startup.
 */
export class FileDeletionLedger implements DeletionLedger {
  private readonly directory: string;
  private readonly repositoryRoot: string;
  private readonly key: Buffer;
  private readonly privacy: PrivateStorageVerifier;

  constructor(options: FileDeletionLedgerOptions) {
    if (
      !isAbsolute(options.directory) ||
      !isAbsolute(options.repositoryRoot) ||
      !Buffer.isBuffer(options.hmacKey) ||
      options.hmacKey.length < 32
    ) {
      throw new DeletionLedgerError('INVALID_CONFIGURATION');
    }
    this.directory = resolve(options.directory);
    this.repositoryRoot = resolve(options.repositoryRoot);
    const relation = relative(this.repositoryRoot, this.directory);
    if (
      !relation ||
      (relation !== '..' &&
        !relation.startsWith(`..${sep}`) &&
        !isAbsolute(relation))
    ) {
      throw new DeletionLedgerError('INVALID_CONFIGURATION');
    }
    this.key = Buffer.from(options.hmacKey);
    this.privacy = options.verifyPrivateStorage ?? assertPrivateStorage;
  }

  private mac(domain: string, body: EntryBody | HeadBody): string {
    return createHmac('sha256', this.key)
      .update(`sportcenter-account-deletion:${domain}:v1\n`)
      .update(JSON.stringify(body))
      .digest('hex');
  }

  private validMac(domain: string, body: EntryBody | HeadBody, mac: unknown) {
    return (
      typeof mac === 'string' &&
      HEX.test(mac) &&
      timingSafeEqual(
        Buffer.from(this.mac(domain, body), 'hex'),
        Buffer.from(mac, 'hex'),
      )
    );
  }

  private digest(entry: Entry): string {
    return createHash('sha256').update(JSON.stringify(entry)).digest('hex');
  }

  private async checkDirectory(): Promise<void> {
    const actual = await realpath(this.directory);
    const same =
      process.platform === 'win32'
        ? actual.toLowerCase() === this.directory.toLowerCase()
        : actual === this.directory;
    if (!same) throw new DeletionLedgerError('UNSAFE_STORAGE');
    await this.privacy(this.directory, 'directory');
    // Reject placement inside any Git checkout, including another repository.
    for (let cursor = this.directory; ; cursor = dirname(cursor)) {
      try {
        await lstat(join(cursor, '.git'));
        throw new DeletionLedgerError('INVALID_CONFIGURATION');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      if (dirname(cursor) === cursor) break;
    }
  }

  private async syncDirectory(): Promise<void> {
    // Windows does not expose a directory handle suitable for fsync via Node.
    // File flushes still happen; filesystem persistence must be operator-verified.
    if (process.platform === 'win32') return;
    const directory = await open(this.directory, 'r');
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }

  private async locked<T>(work: () => Promise<T>): Promise<T> {
    let lock: Awaited<ReturnType<typeof open>> | undefined;
    let result!: T;
    let failure: DeletionLedgerError | undefined;
    const lockPath = join(this.directory, 'deletion.lock');
    try {
      await this.checkDirectory();
      try {
        lock = await open(lockPath, 'wx', 0o600);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
          throw new DeletionLedgerError('LOCKED');
        }
        throw error;
      }
      await this.privacy(lockPath, 'file');
      result = await work();
    } catch (error) {
      failure =
        error instanceof DeletionLedgerError
          ? error
          : new DeletionLedgerError('UNAVAILABLE');
    }
    if (lock) {
      try {
        const held = await lock.stat();
        const current = await lstat(lockPath);
        // Never remove a replacement lock or take over a stale process lock.
        if (held.dev !== current.dev || held.ino !== current.ino) {
          throw new DeletionLedgerError('UNSAFE_STORAGE');
        }
        await lock.close();
        await unlink(lockPath);
      } catch {
        await lock.close().catch(() => undefined);
        failure = new DeletionLedgerError('UNAVAILABLE');
      }
    }
    if (failure) throw failure;
    return result;
  }

  /** Explicit one-time provisioning only; NEVER call when enabling/starting. */
  initializeNew(): Promise<void> {
    return this.locked(async () => {
      for (const name of ['deletions.jsonl', 'deletions.head.json']) {
        try {
          await lstat(join(this.directory, name));
          throw new DeletionLedgerError('CONFLICT');
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        }
      }
      const genesis: Entry = {
        body: {
          version: 1,
          ledgerId: randomUUID(),
          sequence: 0,
          previousDigest: ZERO,
          type: 'genesis',
        },
        mac: '',
      };
      genesis.mac = this.mac('entry', genesis.body);
      const log = await open(
        join(this.directory, 'deletions.jsonl'),
        'wx',
        0o600,
      );
      try {
        await log.writeFile(`${JSON.stringify(genesis)}\n`);
        await log.sync();
      } finally {
        await log.close();
      }
      // An existing head is never overwritten by provisioning.
      await this.writeHead(genesis, true);
      await this.syncDirectory();
    });
  }

  private async writeHead(entry: Entry, initial = false): Promise<void> {
    const head: Head = {
      body: {
        version: 1,
        ledgerId: entry.body.ledgerId,
        sequence: entry.body.sequence,
        digest: this.digest(entry),
      },
      mac: '',
    };
    head.mac = this.mac('head', head.body);
    const destination = join(this.directory, 'deletions.head.json');
    const temporary = initial
      ? destination
      : join(this.directory, `head-${randomUUID()}.tmp`);
    const file = await open(temporary, 'wx', 0o600);
    try {
      await file.writeFile(`${JSON.stringify(head)}\n`);
      await file.sync();
    } finally {
      await file.close();
    }
    await this.privacy(temporary, 'file');
    if (!initial) await rename(temporary, destination);
    await this.syncDirectory();
  }

  private async readVerified(): Promise<{
    snapshot: DeletionLedgerSnapshot;
    last: Entry;
  }> {
    const logPath = join(this.directory, 'deletions.jsonl');
    const headPath = join(this.directory, 'deletions.head.json');
    await this.privacy(logPath, 'file');
    await this.privacy(headPath, 'file');
    const stat = await lstat(logPath);
    const headStat = await lstat(headPath);
    if (stat.size <= 0 || stat.size > MAX_BYTES || headStat.size > 2048) {
      throw new DeletionLedgerError('INTEGRITY_FAILURE');
    }
    const raw = await readFile(logPath, 'utf8');
    if (!raw.endsWith('\n')) throw new DeletionLedgerError('INTEGRITY_FAILURE');
    const lines = raw.slice(0, -1).split('\n');
    const intents = new Map<string, RecordedDeletionIntent>();
    let previous = ZERO;
    let last: Entry | undefined;
    for (const [sequence, line] of lines.entries()) {
      let unknown: unknown;
      try {
        unknown = JSON.parse(line);
      } catch {
        throw new DeletionLedgerError('INTEGRITY_FAILURE');
      }
      if (
        !object(unknown) ||
        !keys(unknown, ['body', 'mac']) ||
        !object(unknown.body)
      ) {
        throw new DeletionLedgerError('INTEGRITY_FAILURE');
      }
      const body = unknown.body;
      const expectedKeys = [
        'version',
        'ledgerId',
        'sequence',
        'previousDigest',
        'type',
      ];
      if (body.type === 'intent')
        expectedKeys.push(
          'operationId',
          'accountId',
          'legacyUserId',
          'legacyFingerprint',
        );
      if (body.type === 'completed') expectedKeys.push('operationId');
      if (body.type === 'retention')
        expectedKeys.push('operationId', 'retention');
      if (
        !keys(body, expectedKeys) ||
        body.version !== 1 ||
        typeof body.ledgerId !== 'string' ||
        !UUID.test(body.ledgerId) ||
        body.sequence !== sequence ||
        body.previousDigest !== previous ||
        (sequence === 0
          ? body.type !== 'genesis'
          : !['intent', 'retention', 'completed'].includes(
              String(body.type),
            )) ||
        (last && body.ledgerId !== last.body.ledgerId) ||
        !this.validMac('entry', body as unknown as EntryBody, unknown.mac)
      )
        throw new DeletionLedgerError('INTEGRITY_FAILURE');
      const entry = unknown as unknown as Entry;
      if (body.type === 'intent') {
        const intent = {
          operationId: body.operationId,
          accountId: body.accountId,
          legacyUserId: body.legacyUserId,
          legacyFingerprint: body.legacyFingerprint,
        };
        if (!validIntent(intent) || intents.has(intent.operationId))
          throw new DeletionLedgerError('INTEGRITY_FAILURE');
        intents.set(intent.operationId, { ...intent, completed: false });
      } else if (body.type === 'retention') {
        const intent =
          typeof body.operationId === 'string'
            ? intents.get(body.operationId)
            : undefined;
        if (
          !intent ||
          intent.completed ||
          intent.retention ||
          !validRetention(body.retention)
        ) {
          throw new DeletionLedgerError('INTEGRITY_FAILURE');
        }
        intent.retention = normalizeRetention(body.retention);
      } else if (body.type === 'completed') {
        const intent =
          typeof body.operationId === 'string'
            ? intents.get(body.operationId)
            : undefined;
        if (!intent || intent.completed)
          throw new DeletionLedgerError('INTEGRITY_FAILURE');
        intent.completed = true;
      }
      previous = this.digest(entry);
      last = entry;
    }
    let unknownHead: unknown;
    try {
      unknownHead = JSON.parse(await readFile(headPath, 'utf8'));
    } catch {
      throw new DeletionLedgerError('INTEGRITY_FAILURE');
    }
    if (
      !last ||
      !object(unknownHead) ||
      !keys(unknownHead, ['body', 'mac']) ||
      !object(unknownHead.body) ||
      !keys(unknownHead.body, ['version', 'ledgerId', 'sequence', 'digest']) ||
      unknownHead.body.version !== 1 ||
      unknownHead.body.ledgerId !== last.body.ledgerId ||
      unknownHead.body.sequence !== last.body.sequence ||
      unknownHead.body.digest !== previous ||
      !this.validMac(
        'head',
        unknownHead.body as unknown as HeadBody,
        unknownHead.mac,
      )
    ) {
      throw new DeletionLedgerError('INTEGRITY_FAILURE');
    }
    return {
      snapshot: {
        sequence: last.body.sequence,
        digest: previous,
        intents: [...intents.values()].map((intent) => ({ ...intent })),
      },
      last,
    };
  }

  verifyAndRead(): Promise<DeletionLedgerSnapshot> {
    return this.locked(async () => (await this.readVerified()).snapshot);
  }

  private async append(
    last: Entry,
    payload: Partial<EntryBody>,
  ): Promise<void> {
    const entry: Entry = {
      body: {
        version: 1,
        ledgerId: last.body.ledgerId,
        sequence: last.body.sequence + 1,
        previousDigest: this.digest(last),
        type: 'intent',
        ...payload,
      },
      mac: '',
    };
    entry.mac = this.mac('entry', entry.body);
    const path = join(this.directory, 'deletions.jsonl');
    const line = `${JSON.stringify(entry)}\n`;
    if ((await lstat(path)).size + Buffer.byteLength(line) > MAX_BYTES)
      throw new DeletionLedgerError('UNAVAILABLE');
    const file = await open(path, 'a');
    try {
      await file.writeFile(line);
      await file.sync();
    } finally {
      await file.close();
    }
    await this.writeHead(entry);
  }

  async recordIntent(intent: DeletionIntent): Promise<void> {
    if (!validIntent(intent)) throw new DeletionLedgerError('INVALID_RECORD');
    const value = normalized(intent);
    await this.locked(async () => {
      const { snapshot, last } = await this.readVerified();
      const existing = snapshot.intents.find(
        (record) => record.operationId === value.operationId,
      );
      if (existing) {
        if (
          existing.accountId !== value.accountId ||
          existing.legacyUserId !== value.legacyUserId ||
          existing.legacyFingerprint !== value.legacyFingerprint
        )
          throw new DeletionLedgerError('CONFLICT');
        return;
      }
      await this.append(last, { type: 'intent', ...value });
    });
  }

  async markCompleted(operationId: string): Promise<void> {
    if (!UUID.test(operationId))
      throw new DeletionLedgerError('INVALID_RECORD');
    await this.locked(async () => {
      const { snapshot, last } = await this.readVerified();
      const intent = snapshot.intents.find(
        (record) => record.operationId === operationId.toLowerCase(),
      );
      if (!intent) throw new DeletionLedgerError('CONFLICT');
      if (!intent.completed)
        await this.append(last, {
          type: 'completed',
          operationId: intent.operationId,
        });
    });
  }

  async recordRetention(
    operationId: string,
    retention: DeletionRetention,
  ): Promise<void> {
    if (!UUID.test(operationId) || !validRetention(retention)) {
      throw new DeletionLedgerError('INVALID_RECORD');
    }
    const value = normalizeRetention(retention);
    await this.locked(async () => {
      const { snapshot, last } = await this.readVerified();
      const intent = snapshot.intents.find(
        (record) => record.operationId === operationId.toLowerCase(),
      );
      if (!intent) throw new DeletionLedgerError('CONFLICT');
      if (intent.retention) {
        if (JSON.stringify(intent.retention) !== JSON.stringify(value))
          throw new DeletionLedgerError('CONFLICT');
        return;
      }
      if (intent.completed) throw new DeletionLedgerError('CONFLICT');
      await this.append(last, {
        type: 'retention',
        operationId: intent.operationId,
        retention: value,
      });
    });
  }
}
