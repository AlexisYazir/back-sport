export interface DeletionIntent {
  operationId: string;
  accountId: string;
  legacyUserId: number;
  /** Keyed digest of the legacy identity; never an email, name or credential. */
  legacyFingerprint: string;
}

export interface DeletionRetention {
  until: string;
  basisHash: string;
  categories: readonly ('orders' | 'payments' | 'returns')[];
}

export interface RecordedDeletionIntent extends DeletionIntent {
  completed: boolean;
  retention?: Readonly<DeletionRetention>;
}

export interface DeletionLedgerSnapshot {
  sequence: number;
  digest: string;
  intents: readonly RecordedDeletionIntent[];
}

export interface DeletionLedger {
  verifyAndRead(): Promise<DeletionLedgerSnapshot>;
  recordIntent(intent: DeletionIntent): Promise<void>;
  recordRetention(
    operationId: string,
    retention: DeletionRetention,
  ): Promise<void>;
  markCompleted(operationId: string): Promise<void>;
}

export class DeletionLedgerError extends Error {
  constructor(
    readonly code:
      | 'INVALID_CONFIGURATION'
      | 'INVALID_RECORD'
      | 'UNSAFE_STORAGE'
      | 'UNAVAILABLE'
      | 'LOCKED'
      | 'INTEGRITY_FAILURE'
      | 'CONFLICT',
  ) {
    // Deliberately exclude records, paths, provider errors and key material.
    super(`ACCOUNT_DELETION_LEDGER_${code}`);
    this.name = 'DeletionLedgerError';
  }
}
