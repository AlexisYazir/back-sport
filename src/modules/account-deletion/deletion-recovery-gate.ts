import {
  DeletionLedger,
  RecordedDeletionIntent,
} from './ledger/deletion-ledger';

export type DeletionReplayResult = 'completed' | 'restricted';

export type DeletionRecoveryState =
  | 'disabled'
  | 'closed'
  | 'recovering'
  | 'ready';

export class DeletionRecoveryGate {
  private current: DeletionRecoveryState;
  private generation = 0;

  constructor(
    readonly enabled: boolean,
    private readonly ledger?: DeletionLedger,
  ) {
    this.current = enabled ? 'closed' : 'disabled';
  }

  get state(): DeletionRecoveryState {
    return this.current;
  }

  /** Ordinary traffic retains its existing behavior when this feature is off. */
  assertApplicationReady(): void {
    if (this.enabled && this.current !== 'ready') {
      throw new Error('ACCOUNT_DELETION_RECOVERY_NOT_READY');
    }
  }

  assertDeletionReady(): void {
    if (!this.enabled) throw new Error('ACCOUNT_DELETION_DISABLED');
    this.assertApplicationReady();
  }

  invalidate(): void {
    if (this.enabled) {
      this.generation += 1;
      this.current = 'closed';
    }
  }

  /**
   * Call before accepting traffic or starting scheduled/background jobs.
   * Replay MUST be idempotent and MUST run for completed intents too: restoring
   * an older DB may resurrect an account whose ledger entry is already complete.
   */
  async reconcileBeforeServing(
    replay: (
      intent: Readonly<RecordedDeletionIntent>,
    ) => Promise<DeletionReplayResult>,
  ): Promise<void> {
    if (!this.enabled) return;
    if (this.current === 'recovering') {
      throw new Error('ACCOUNT_DELETION_RECOVERY_ALREADY_RUNNING');
    }
    this.current = 'recovering';
    const generation = this.generation;
    try {
      if (!this.ledger) throw new Error('ACCOUNT_DELETION_LEDGER_REQUIRED');
      for (let pass = 0; pass < 5; pass += 1) {
        const before = await this.ledger.verifyAndRead();
        const expectedCompletions = new Map(
          before.intents.map((record) => [
            record.operationId,
            record.completed,
          ]),
        );
        for (const record of before.intents) {
          const copy: Readonly<RecordedDeletionIntent> = Object.freeze({
            ...record,
            ...(record.retention
              ? {
                  retention: Object.freeze({
                    ...record.retention,
                    categories: Object.freeze([...record.retention.categories]),
                  }),
                }
              : {}),
          });
          const result = await replay(copy);
          if (
            !['completed', 'restricted'].includes(result) ||
            (record.completed && result !== 'completed')
          ) {
            throw new Error('ACCOUNT_DELETION_REPLAY_INCOMPLETE');
          }
          if (result === 'completed') {
            expectedCompletions.set(record.operationId, true);
            if (!record.completed)
              await this.ledger.markCompleted(record.operationId);
          }
        }
        const after = await this.ledger.verifyAndRead();
        // Our own completion events do not add intents. New external intents
        // require another pass before this process may serve restored data.
        if (
          after.intents.length === before.intents.length &&
          after.intents.every((record, index) => {
            const prior = before.intents[index];
            return (
              prior.operationId === record.operationId &&
              prior.accountId === record.accountId &&
              prior.legacyUserId === record.legacyUserId &&
              prior.legacyFingerprint === record.legacyFingerprint &&
              JSON.stringify(prior.retention ?? null) ===
                JSON.stringify(record.retention ?? null) &&
              expectedCompletions.get(record.operationId) === record.completed
            );
          })
        ) {
          const stable = await this.ledger.verifyAndRead();
          if (
            stable.sequence === after.sequence &&
            stable.digest === after.digest
          ) {
            if (this.generation !== generation)
              throw new Error('ACCOUNT_DELETION_RECOVERY_INVALIDATED');
            this.current = 'ready';
            return;
          }
        }
      }
      throw new Error('ACCOUNT_DELETION_LEDGER_NOT_QUIESCENT');
    } catch {
      this.current = 'closed';
      throw new Error('ACCOUNT_DELETION_RECOVERY_FAILED');
    }
  }
}
