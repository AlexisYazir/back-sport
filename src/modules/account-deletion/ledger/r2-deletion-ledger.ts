import {
  GetObjectCommand,
  GetObjectCommandOutput,
  PutObjectCommand,
} from '@aws-sdk/client-s3';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import {
  DeletionIntent,
  DeletionLedger,
  DeletionLedgerError,
  DeletionLedgerSnapshot,
  DeletionRetention,
  RecordedDeletionIntent,
} from './deletion-ledger';

/** Deliberately small transport contract: no list/delete/bucket administration. */
export interface R2DeletionClient {
  send(
    command: GetObjectCommand,
  ): Promise<Pick<GetObjectCommandOutput, 'Body' | 'ETag' | 'ContentLength'>>;
  send(command: PutObjectCommand): Promise<unknown>;
}

export interface R2DeletionLedgerOptions {
  client: R2DeletionClient;
  bucket: string;
  /** Stable logical database binding, independent of host/password/JWT rotation. */
  prefix: string;
  /** Existing application root secret, used ONLY to wrap new random secrets. */
  wrappingSecret: string;
  databaseHasHistory: boolean;
  expectedLedgerId?: string;
}

interface Secrets {
  ledgerId: string;
  operationSecret: string;
  ledgerSecret: string;
}
interface ManifestBody {
  version: 1;
  ledgerId: string;
  phase: 'provisioning' | 'active';
  salt: string;
  iv: string;
  ciphertext: string;
  tag: string;
}
interface Manifest {
  body: ManifestBody;
  mac: string;
}
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
interface SnapshotDocument {
  version: 1;
  ledgerId: string;
  entries: Entry[];
  mac: string;
}
interface StoredObject {
  raw: string;
  etag: string;
}
interface VerifiedSnapshot {
  document: SnapshotDocument;
  snapshot: DeletionLedgerSnapshot;
  etag: string;
}

const ZERO = '0'.repeat(64);
const HEX = /^[a-f\d]{64}$/;
const UUID =
  /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_ATTEMPTS = 32;

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
      (category: unknown) =>
        typeof category === 'string' &&
        ['orders', 'payments', 'returns'].includes(category),
    ) &&
    new Set(value.categories).size === value.categories.length
  );
}
function normalizeRetention(value: DeletionRetention): DeletionRetention {
  return { ...value, categories: [...value.categories].sort() };
}
function mac(key: Buffer, domain: string, body: unknown): string {
  return createHmac('sha256', key)
    .update(`sportcenter-account-deletion:r2:${domain}:v1\n`)
    .update(JSON.stringify(body))
    .digest('hex');
}
function validMac(key: Buffer, domain: string, body: unknown, value: unknown) {
  return (
    typeof value === 'string' &&
    HEX.test(value) &&
    timingSafeEqual(
      Buffer.from(mac(key, domain, body), 'hex'),
      Buffer.from(value, 'hex'),
    )
  );
}
function digest(entry: Entry): string {
  return createHash('sha256').update(JSON.stringify(entry)).digest('hex');
}
function fail(): never {
  throw new DeletionLedgerError('INTEGRITY_FAILURE');
}
function parse(raw: string): unknown {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return fail();
  }
  // Canonical encoding also rejects duplicate JSON keys and hidden extra bytes.
  if (JSON.stringify(value) !== raw) return fail();
  return value;
}
function status(error: unknown): number | undefined {
  if (!object(error) || !object(error.$metadata)) return undefined;
  return typeof error.$metadata.httpStatusCode === 'number'
    ? error.$metadata.httpStatusCode
    : undefined;
}
function isMissing(error: unknown): boolean {
  return status(error) === 404;
}
function isCasConflict(error: unknown): boolean {
  return status(error) === 409 || status(error) === 412;
}
async function sanitized<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    throw error instanceof DeletionLedgerError
      ? error
      : new DeletionLedgerError('UNAVAILABLE');
  }
}

/**
 * A private R2 manifest survives a database-only restore. A full, authenticated
 * journal snapshot is replaced with If-Match; acknowledged entries are never
 * removed. Neither object belongs in database dumps or backup cleanup paths.
 * Restoring/removing BOTH the object store and database is outside this contract.
 * A rotated wrapping root must be recovered/rewrapped; it never starts a new log.
 */
export class R2DeletionLedger implements DeletionLedger {
  private queue: Promise<void> = Promise.resolve();
  private seen: { sequence: number; digest: string } | undefined;
  private readonly key: Buffer;

  private constructor(
    private readonly options: R2DeletionLedgerOptions,
    private readonly secrets: Secrets,
  ) {
    this.key = Buffer.from(secrets.ledgerSecret, 'hex');
  }

  static open(options: R2DeletionLedgerOptions): Promise<{
    ledger: R2DeletionLedger;
    ledgerId: string;
    operationSecret: string;
    ledgerSecret: string;
  }> {
    return sanitized(async () => {
      if (
        !options.client ||
        typeof options.client.send !== 'function' ||
        typeof options.bucket !== 'string' ||
        !/^[a-z\d][a-z\d.-]{1,61}[a-z\d]$/.test(options.bucket) ||
        !/^_account-deletion\/v1\/[a-f\d]{64}\/$/.test(options.prefix) ||
        typeof options.wrappingSecret !== 'string' ||
        Buffer.byteLength(options.wrappingSecret) < 32 ||
        typeof options.databaseHasHistory !== 'boolean' ||
        (options.expectedLedgerId !== undefined &&
          !UUID.test(options.expectedLedgerId))
      )
        throw new DeletionLedgerError('INVALID_CONFIGURATION');

      // Copy scalar options so a caller cannot change the target/key after open.
      options = { ...options };
      const provisional = new R2DeletionLedger(options, {
        ledgerId: randomUUID(),
        operationSecret: randomBytes(32).toString('hex'),
        ledgerSecret: randomBytes(32).toString('hex'),
      });
      let stored = await provisional.readObject('manifest.json', 8192);
      if (!stored) {
        if (
          options.databaseHasHistory ||
          options.expectedLedgerId ||
          (await provisional.readObject('snapshot.json', MAX_BYTES))
        )
          return fail();
        const manifest = provisional.newManifest();
        try {
          await provisional.put('manifest.json', manifest, {
            IfNoneMatch: '*',
          });
        } catch (error) {
          // Ambiguous success may have committed. Never overwrite/re-key it.
          stored = await provisional.readObject('manifest.json', 8192);
          if (!stored) {
            if (isCasConflict(error)) throw new DeletionLedgerError('CONFLICT');
            throw error;
          }
        }
        stored ??= await provisional.readObject('manifest.json', 8192);
      }
      if (!stored) return fail();
      const decoded = provisional.decodeManifest(stored.raw);
      if (
        options.expectedLedgerId &&
        options.expectedLedgerId.toLowerCase() !== decoded.secrets.ledgerId
      )
        throw new DeletionLedgerError('CONFLICT');
      const ledger = new R2DeletionLedger(options, decoded.secrets);

      if (decoded.manifest.body.phase === 'provisioning') {
        let snapshot = await ledger.readObject('snapshot.json', MAX_BYTES);
        if (!snapshot) {
          if (options.databaseHasHistory || options.expectedLedgerId)
            return fail();
          const genesis = ledger.entry({ type: 'genesis' }, 0, ZERO);
          try {
            await ledger.put('snapshot.json', ledger.document([genesis]), {
              IfNoneMatch: '*',
            });
          } catch (error) {
            // If any write result is uncertain, observe the durable value first.
            snapshot = await ledger.readObject('snapshot.json', MAX_BYTES);
            if (!snapshot) throw error;
          }
          snapshot ??= await ledger.readObject('snapshot.json', MAX_BYTES);
        }
        if (!snapshot) return fail();
        // A concurrently activated peer may already have appended. Re-read the
        // manifest before judging whether a non-genesis snapshot is legitimate.
        const currentManifest = await ledger.readObject('manifest.json', 8192);
        if (!currentManifest) return fail();
        const current = ledger.decodeOwnManifest(currentManifest.raw);
        const verified = ledger.verifyDocument(snapshot);
        if (current.body.phase === 'provisioning') {
          if (verified.snapshot.sequence !== 0 || options.databaseHasHistory)
            return fail();
          const activeBody: ManifestBody = { ...current.body, phase: 'active' };
          const active: Manifest = {
            body: activeBody,
            mac: mac(ledger.key, 'manifest', activeBody),
          };
          try {
            await ledger.put('manifest.json', active, {
              IfMatch: currentManifest.etag,
            });
          } catch (error) {
            const observed = await ledger.readObject('manifest.json', 8192);
            if (
              !observed ||
              ledger.decodeOwnManifest(observed.raw).body.phase !== 'active'
            )
              throw error;
          }
        }
      }
      await ledger.readVerified();
      return { ledger, ...ledger.secrets };
    });
  }

  private wrappingKey(salt: Buffer): Buffer {
    return Buffer.from(
      hkdfSync(
        'sha256',
        Buffer.from(this.options.wrappingSecret, 'utf8'),
        salt,
        Buffer.from(
          `sportcenter-account-deletion:r2:wrap:v1\n${this.options.bucket}\n${this.options.prefix}`,
        ),
        32,
      ),
    );
  }
  private aad(ledgerId: string): Buffer {
    return Buffer.from(
      `sportcenter-account-deletion:r2:manifest:v1\n${this.options.bucket}\n${this.options.prefix}\n${ledgerId}`,
    );
  }
  private newManifest(): Manifest {
    const salt = randomBytes(32),
      iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.wrappingKey(salt), iv);
    cipher.setAAD(this.aad(this.secrets.ledgerId));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(this.secrets), 'utf8'),
      cipher.final(),
    ]);
    const body: ManifestBody = {
      version: 1,
      ledgerId: this.secrets.ledgerId,
      phase: 'provisioning',
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      ciphertext: ciphertext.toString('hex'),
      tag: cipher.getAuthTag().toString('hex'),
    };
    return { body, mac: mac(this.key, 'manifest', body) };
  }
  private decodeManifest(raw: string): {
    manifest: Manifest;
    secrets: Secrets;
  } {
    const value = parse(raw);
    if (!object(value) || !keys(value, ['body', 'mac']) || !object(value.body))
      return fail();
    const body = value.body;
    if (
      !keys(body, [
        'version',
        'ledgerId',
        'phase',
        'salt',
        'iv',
        'ciphertext',
        'tag',
      ]) ||
      body.version !== 1 ||
      typeof body.ledgerId !== 'string' ||
      !UUID.test(body.ledgerId) ||
      !['provisioning', 'active'].includes(String(body.phase)) ||
      typeof body.salt !== 'string' ||
      !HEX.test(body.salt) ||
      typeof body.iv !== 'string' ||
      !/^[a-f\d]{24}$/.test(body.iv) ||
      typeof body.tag !== 'string' ||
      !/^[a-f\d]{32}$/.test(body.tag) ||
      typeof body.ciphertext !== 'string' ||
      !/^(?:[a-f\d]{2}){1,2048}$/.test(body.ciphertext)
    )
      return fail();
    let secrets: unknown;
    try {
      const decipher = createDecipheriv(
        'aes-256-gcm',
        this.wrappingKey(Buffer.from(body.salt, 'hex')),
        Buffer.from(body.iv, 'hex'),
      );
      decipher.setAAD(this.aad(body.ledgerId));
      decipher.setAuthTag(Buffer.from(body.tag, 'hex'));
      secrets = parse(
        Buffer.concat([
          decipher.update(Buffer.from(body.ciphertext, 'hex')),
          decipher.final(),
        ]).toString('utf8'),
      );
    } catch {
      return fail();
    }
    if (
      !object(secrets) ||
      !keys(secrets, ['ledgerId', 'operationSecret', 'ledgerSecret']) ||
      secrets.ledgerId !== body.ledgerId ||
      typeof secrets.operationSecret !== 'string' ||
      !HEX.test(secrets.operationSecret) ||
      typeof secrets.ledgerSecret !== 'string' ||
      !HEX.test(secrets.ledgerSecret) ||
      secrets.operationSecret === secrets.ledgerSecret ||
      !validMac(
        Buffer.from(secrets.ledgerSecret, 'hex'),
        'manifest',
        body,
        value.mac,
      )
    )
      return fail();
    return {
      manifest: value as unknown as Manifest,
      secrets: secrets as unknown as Secrets,
    };
  }
  private decodeOwnManifest(raw: string): Manifest {
    const decoded = this.decodeManifest(raw);
    if (JSON.stringify(decoded.secrets) !== JSON.stringify(this.secrets))
      return fail();
    return decoded.manifest;
  }

  private async readObject(
    name: string,
    limit: number,
  ): Promise<StoredObject | null> {
    let response: Pick<
      GetObjectCommandOutput,
      'Body' | 'ETag' | 'ContentLength'
    >;
    try {
      response = await this.options.client.send(
        new GetObjectCommand({
          Bucket: this.options.bucket,
          Key: this.options.prefix + name,
        }),
      );
    } catch (error) {
      if (isMissing(error)) return null;
      throw error;
    }
    if (
      typeof response.ETag !== 'string' ||
      !response.ETag ||
      response.ETag.length > 256 ||
      /[\r\n]/.test(response.ETag) ||
      (response.ContentLength !== undefined &&
        (response.ContentLength <= 0 || response.ContentLength > limit)) ||
      !response.Body ||
      !(Symbol.asyncIterator in response.Body)
    )
      return fail();
    let length = 0;
    const chunks: Buffer[] = [];
    for await (const chunk of response.Body as AsyncIterable<unknown>) {
      if (!(chunk instanceof Uint8Array) && typeof chunk !== 'string')
        return fail();
      const bytes = Buffer.from(chunk);
      length += bytes.length;
      if (length > limit) return fail();
      chunks.push(bytes);
    }
    if (
      !length ||
      (response.ContentLength !== undefined &&
        length !== response.ContentLength)
    )
      return fail();
    return { raw: Buffer.concat(chunks).toString('utf8'), etag: response.ETag };
  }
  private async put(
    name: string,
    value: unknown,
    condition: { IfMatch: string } | { IfNoneMatch: '*' },
  ): Promise<void> {
    const body = Buffer.from(JSON.stringify(value), 'utf8');
    if (body.length > MAX_BYTES) throw new DeletionLedgerError('UNAVAILABLE');
    await this.options.client.send(
      new PutObjectCommand({
        Bucket: this.options.bucket,
        Key: this.options.prefix + name,
        Body: body,
        ContentLength: body.length,
        ContentType: 'application/json',
        CacheControl: 'no-store',
        ...condition,
      }),
    );
  }
  private entry(
    payload: Partial<EntryBody>,
    sequence: number,
    previousDigest: string,
  ): Entry {
    const body: EntryBody = {
      version: 1,
      ledgerId: this.secrets.ledgerId,
      sequence,
      previousDigest,
      type: 'intent',
      ...payload,
    };
    return { body, mac: mac(this.key, 'entry', body) };
  }
  private document(entries: Entry[]): SnapshotDocument {
    const body = {
      version: 1 as const,
      ledgerId: this.secrets.ledgerId,
      entries,
    };
    return { ...body, mac: mac(this.key, 'snapshot', body) };
  }
  private verifyDocument(stored: StoredObject): VerifiedSnapshot {
    const unknown = parse(stored.raw);
    if (
      !object(unknown) ||
      !keys(unknown, ['version', 'ledgerId', 'entries', 'mac']) ||
      unknown.version !== 1 ||
      unknown.ledgerId !== this.secrets.ledgerId ||
      !Array.isArray(unknown.entries) ||
      !unknown.entries.length ||
      !validMac(
        this.key,
        'snapshot',
        {
          version: unknown.version,
          ledgerId: unknown.ledgerId,
          entries: unknown.entries,
        },
        unknown.mac,
      )
    )
      return fail();
    const intents = new Map<string, RecordedDeletionIntent>();
    let previous = ZERO;
    for (const [sequence, entry] of unknown.entries.entries()) {
      if (
        !object(entry) ||
        !keys(entry, ['body', 'mac']) ||
        !object(entry.body)
      )
        return fail();
      const body = entry.body;
      const expected = [
        'version',
        'ledgerId',
        'sequence',
        'previousDigest',
        'type',
      ];
      if (body.type === 'intent')
        expected.push(
          'operationId',
          'accountId',
          'legacyUserId',
          'legacyFingerprint',
        );
      if (body.type === 'retention') expected.push('operationId', 'retention');
      if (body.type === 'completed') expected.push('operationId');
      if (
        !keys(body, expected) ||
        body.version !== 1 ||
        body.ledgerId !== this.secrets.ledgerId ||
        body.sequence !== sequence ||
        body.previousDigest !== previous ||
        (sequence === 0
          ? body.type !== 'genesis'
          : !['intent', 'retention', 'completed'].includes(
              String(body.type),
            )) ||
        !validMac(this.key, 'entry', body, entry.mac)
      )
        return fail();
      if (body.type === 'intent') {
        const value = {
          operationId: body.operationId,
          accountId: body.accountId,
          legacyUserId: body.legacyUserId,
          legacyFingerprint: body.legacyFingerprint,
        };
        if (
          !validIntent(value) ||
          intents.has(value.operationId) ||
          value.operationId !== value.operationId.toLowerCase() ||
          value.accountId !== value.accountId.toLowerCase()
        )
          return fail();
        intents.set(value.operationId, { ...value, completed: false });
      } else if (body.type === 'retention') {
        const value =
          typeof body.operationId === 'string'
            ? intents.get(body.operationId)
            : undefined;
        if (
          !value ||
          value.completed ||
          value.retention ||
          !validRetention(body.retention)
        )
          return fail();
        value.retention = normalizeRetention(body.retention);
      } else if (body.type === 'completed') {
        const value =
          typeof body.operationId === 'string'
            ? intents.get(body.operationId)
            : undefined;
        if (!value || value.completed) return fail();
        value.completed = true;
      }
      previous = digest(entry as unknown as Entry);
      if (this.seen?.sequence === sequence && this.seen.digest !== previous)
        return fail();
    }
    const sequence = unknown.entries.length - 1;
    if (this.seen && sequence < this.seen.sequence) return fail();
    this.seen = { sequence, digest: previous };
    return {
      document: unknown as unknown as SnapshotDocument,
      etag: stored.etag,
      snapshot: { sequence, digest: previous, intents: [...intents.values()] },
    };
  }
  private async readVerified(): Promise<VerifiedSnapshot> {
    const manifest = await this.readObject('manifest.json', 8192);
    if (
      !manifest ||
      this.decodeOwnManifest(manifest.raw).body.phase !== 'active'
    )
      return fail();
    const snapshot = await this.readObject('snapshot.json', MAX_BYTES);
    if (!snapshot) return fail();
    return this.verifyDocument(snapshot);
  }
  private locked<T>(work: () => Promise<T>): Promise<T> {
    const operation = this.queue.then(() => sanitized(work));
    this.queue = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  }
  verifyAndRead(): Promise<DeletionLedgerSnapshot> {
    return this.locked(async () => (await this.readVerified()).snapshot);
  }
  private mutate(
    change: (snapshot: DeletionLedgerSnapshot) => Partial<EntryBody> | null,
  ): Promise<void> {
    return this.locked(async () => {
      for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        const verified = await this.readVerified();
        const payload = change(verified.snapshot);
        if (!payload) return;
        const next = this.document([
          ...verified.document.entries,
          this.entry(
            payload,
            verified.snapshot.sequence + 1,
            verified.snapshot.digest,
          ),
        ]);
        try {
          await this.put('snapshot.json', next, { IfMatch: verified.etag });
          // Observe/verify even an acknowledged write before returning success.
          const observed = await this.readVerified();
          if (change(observed.snapshot) !== null)
            throw new DeletionLedgerError('UNAVAILABLE');
          return;
        } catch (error) {
          if (isCasConflict(error)) continue;
          // Network timeouts can occur after commit. Reconcile idempotently, but
          // NEVER retry an ambiguous write against an unobserved/new ETag.
          const observed = await this.readVerified();
          if (change(observed.snapshot) === null) return;
          throw error;
        }
      }
      throw new DeletionLedgerError('UNAVAILABLE');
    });
  }
  recordIntent(intent: DeletionIntent): Promise<void> {
    if (!validIntent(intent))
      return Promise.reject(new DeletionLedgerError('INVALID_RECORD'));
    const value = {
      ...intent,
      operationId: intent.operationId.toLowerCase(),
      accountId: intent.accountId.toLowerCase(),
    };
    return this.mutate((snapshot) => {
      const existing = snapshot.intents.find(
        (record) => record.operationId === value.operationId,
      );
      if (!existing) return { type: 'intent', ...value };
      if (
        existing.accountId !== value.accountId ||
        existing.legacyUserId !== value.legacyUserId ||
        existing.legacyFingerprint !== value.legacyFingerprint
      )
        throw new DeletionLedgerError('CONFLICT');
      return null;
    });
  }
  markCompleted(operationId: string): Promise<void> {
    if (!UUID.test(operationId))
      return Promise.reject(new DeletionLedgerError('INVALID_RECORD'));
    return this.mutate((snapshot) => {
      const existing = snapshot.intents.find(
        (record) => record.operationId === operationId.toLowerCase(),
      );
      if (!existing) throw new DeletionLedgerError('CONFLICT');
      return existing.completed
        ? null
        : { type: 'completed', operationId: existing.operationId };
    });
  }
  recordRetention(
    operationId: string,
    retention: DeletionRetention,
  ): Promise<void> {
    if (!UUID.test(operationId) || !validRetention(retention))
      return Promise.reject(new DeletionLedgerError('INVALID_RECORD'));
    const value = normalizeRetention(retention);
    return this.mutate((snapshot) => {
      const existing = snapshot.intents.find(
        (record) => record.operationId === operationId.toLowerCase(),
      );
      if (!existing) throw new DeletionLedgerError('CONFLICT');
      if (existing.retention) {
        if (JSON.stringify(existing.retention) !== JSON.stringify(value))
          throw new DeletionLedgerError('CONFLICT');
        return null;
      }
      if (existing.completed) throw new DeletionLedgerError('CONFLICT');
      return {
        type: 'retention',
        operationId: existing.operationId,
        retention: value,
      };
    });
  }
}
