import { randomBytes, randomUUID } from 'node:crypto';
import {
  DeletionRecoveryGate,
  DeletionReplayResult,
} from './deletion-recovery-gate';
import {
  DeletionLedger,
  DeletionLedgerSnapshot,
  RecordedDeletionIntent,
} from './ledger/deletion-ledger';

function record(completed = false): RecordedDeletionIntent {
  return {
    operationId: randomUUID(),
    accountId: randomUUID(),
    legacyUserId: 9,
    legacyFingerprint: randomBytes(32).toString('hex'),
    completed,
  };
}
function fixture(initial: RecordedDeletionIntent[] = []) {
  const records = initial.map((value) => ({ ...value }));
  let sequence = records.length;
  const read = jest
    .fn<Promise<DeletionLedgerSnapshot>, []>()
    .mockImplementation(() =>
      Promise.resolve({
        sequence,
        digest: `digest-${sequence}`,
        intents: records.map((value) => ({ ...value })),
      }),
    );
  const complete = jest
    .fn<Promise<void>, [string]>()
    .mockImplementation((operationId) => {
      const target = records.find((value) => value.operationId === operationId);
      if (!target) return Promise.reject(new Error('NOT_FOUND'));
      target.completed = true;
      sequence += 1;
      return Promise.resolve();
    });
  const ledger: DeletionLedger = {
    verifyAndRead: read,
    markCompleted: complete,
    recordIntent: jest.fn(),
    recordRetention: jest.fn(),
  };
  const gate = new DeletionRecoveryGate(true, ledger);
  return { records, read, complete, ledger, gate };
}

describe('DeletionRecoveryGate', () => {
  test('feature off never reads ledger or invokes replay; existing traffic remains unaffected', async () => {
    const { ledger, read } = fixture();
    const replay = jest.fn<
      Promise<DeletionReplayResult>,
      [Readonly<RecordedDeletionIntent>]
    >();
    const gate = new DeletionRecoveryGate(false, ledger);
    await gate.reconcileBeforeServing(replay);
    expect(gate.state).toBe('disabled');
    expect(() => gate.assertApplicationReady()).not.toThrow();
    expect(() => gate.assertDeletionReady()).toThrow(
      'ACCOUNT_DELETION_DISABLED',
    );
    expect(read).not.toHaveBeenCalled();
    expect(replay).not.toHaveBeenCalled();
  });

  test('enabled starts closed until ledger verification and replay complete', async () => {
    const { gate } = fixture();
    expect(gate.state).toBe('closed');
    expect(() => gate.assertApplicationReady()).toThrow('NOT_READY');
    await gate.reconcileBeforeServing(() =>
      Promise.resolve('completed' as const),
    );
    expect(gate.state).toBe('ready');
    expect(() => gate.assertApplicationReady()).not.toThrow();
    expect(() => gate.assertDeletionReady()).not.toThrow();
  });

  test('feature enabled without an independently configured ledger fails closed', async () => {
    const gate = new DeletionRecoveryGate(true);
    await expect(
      gate.reconcileBeforeServing(() => Promise.resolve('completed' as const)),
    ).rejects.toThrow('RECOVERY_FAILED');
    expect(gate.state).toBe('closed');
  });

  test('replays completed entries too when restoring an older database', async () => {
    const initial = record(true);
    const { gate, complete } = fixture([initial]);
    const replay = jest
      .fn<Promise<DeletionReplayResult>, [Readonly<RecordedDeletionIntent>]>()
      .mockResolvedValue('completed');
    await gate.reconcileBeforeServing(replay);
    const intent: RecordedDeletionIntent = {
      completed: initial.completed,
      operationId: initial.operationId,
      accountId: initial.accountId,
      legacyUserId: initial.legacyUserId,
      legacyFingerprint: initial.legacyFingerprint,
    };
    expect(replay).toHaveBeenCalledWith(intent);
    expect(Object.isFrozen(replay.mock.calls[0][0])).toBe(true);
    expect(complete).not.toHaveBeenCalled();
  });

  test('marks unfinished intents complete only after successful idempotent replay', async () => {
    const initial = record();
    const { gate, complete, records } = fixture([initial]);
    const events: string[] = [];
    complete.mockImplementation(() => {
      events.push('complete');
      records[0].completed = true;
      return Promise.resolve();
    });
    await gate.reconcileBeforeServing(() => {
      events.push('replay');
      return Promise.resolve('completed' as const);
    });
    expect(events).toEqual(['replay', 'complete']);
    expect(gate.state).toBe('ready');
  });

  test.each(['read', 'replay', 'complete'] as const)(
    'a %s failure leaves traffic and jobs gated without private details',
    async (stage) => {
      const { gate, read, complete } = fixture([record()]);
      const failure = new Error('CANARY_PRIVATE_DETAILS');
      if (stage === 'read') read.mockRejectedValue(failure);
      if (stage === 'complete') complete.mockRejectedValue(failure);
      const replay = jest
        .fn<Promise<DeletionReplayResult>, [Readonly<RecordedDeletionIntent>]>()
        .mockImplementation(() =>
          stage === 'replay'
            ? Promise.reject(failure)
            : Promise.resolve('completed' as const),
        );
      await expect(gate.reconcileBeforeServing(replay)).rejects.toThrow(
        'ACCOUNT_DELETION_RECOVERY_FAILED',
      );
      expect(gate.state).toBe('closed');
      expect(() => gate.assertApplicationReady()).toThrow('NOT_READY');
    },
  );

  test('a restricted pending request reapplies its block without falsely marking deletion completed', async () => {
    const initial = record();
    const { gate, complete } = fixture([initial]);
    const replay = jest
      .fn<Promise<DeletionReplayResult>, [Readonly<RecordedDeletionIntent>]>()
      .mockResolvedValue('restricted');
    await gate.reconcileBeforeServing(replay);
    expect(replay).toHaveBeenCalledWith(initial);
    expect(complete).not.toHaveBeenCalled();
    expect(gate.state).toBe('ready');
    expect(() => gate.assertApplicationReady()).not.toThrow();
  });

  test('retention deadlines are included in the immutable replay record after restoring an older database', async () => {
    const initial = {
      ...record(true),
      retention: {
        until: '2030-01-02T03:04:05.000Z',
        basisHash: randomBytes(32).toString('hex'),
        categories: ['orders' as const],
      },
    };
    const { gate } = fixture([initial]);
    const replay = jest
      .fn<Promise<DeletionReplayResult>, [Readonly<RecordedDeletionIntent>]>()
      .mockResolvedValue('completed');
    await gate.reconcileBeforeServing(replay);
    expect(replay).toHaveBeenCalledWith(initial);
    const result = replay.mock.calls[0][0].retention;
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result?.categories)).toBe(true);
    expect(result?.until).toBe(initial.retention.until);
  });

  test('a retention append while applying an intent requires replay of the updated durable record', async () => {
    const initial = record(true);
    const { gate, records } = fixture([initial]);
    const retention = {
      until: '2030-01-02T03:04:05.000Z',
      basisHash: randomBytes(32).toString('hex'),
      categories: ['orders' as const],
    };
    const replay = jest
      .fn<Promise<DeletionReplayResult>, [Readonly<RecordedDeletionIntent>]>()
      .mockImplementation(() => {
        if (!records[0].retention) records[0].retention = retention;
        return Promise.resolve('completed');
      });
    await gate.reconcileBeforeServing(replay);
    expect(replay).toHaveBeenCalledTimes(2);
    expect(replay.mock.calls[1][0].retention).toEqual(retention);
  });

  test('a previously completed deletion cannot be downgraded to a restricted pending request', async () => {
    const { gate } = fixture([record(true)]);
    await expect(
      gate.reconcileBeforeServing(() => Promise.resolve('restricted')),
    ).rejects.toThrow('RECOVERY_FAILED');
    expect(gate.state).toBe('closed');
  });

  test('invalidation while replay is running cannot accidentally reopen traffic', async () => {
    const { gate } = fixture([record(true)]);
    await expect(
      gate.reconcileBeforeServing(() => {
        gate.invalidate();
        return Promise.resolve('completed');
      }),
    ).rejects.toThrow('RECOVERY_FAILED');
    expect(gate.state).toBe('closed');
  });

  test('repeats reconciliation if another process appends an intent meanwhile', async () => {
    const first = record(true);
    const added = record(true);
    const { gate, records } = fixture([first]);
    const replay = jest
      .fn<Promise<DeletionReplayResult>, [Readonly<RecordedDeletionIntent>]>()
      .mockImplementation(() => {
        if (records.length === 1) records.push(added);
        return Promise.resolve('completed' as const);
      });
    await gate.reconcileBeforeServing(replay);
    expect(replay.mock.calls.map(([value]) => value.operationId)).toEqual([
      first.operationId,
      first.operationId,
      added.operationId,
    ]);
    expect(gate.state).toBe('ready');
  });

  test('continued external appends do not let readiness succeed', async () => {
    const { gate, records } = fixture([record(true)]);
    await expect(
      gate.reconcileBeforeServing(() => {
        records.push(record(true));
        return Promise.resolve('completed' as const);
      }),
    ).rejects.toThrow('RECOVERY_FAILED');
    expect(gate.state).toBe('closed');
  });

  test('readiness stays closed during an outstanding replay and rejects a second startup', async () => {
    const { gate } = fixture([record()]);
    let finish!: (result: DeletionReplayResult) => void;
    const blocked = new Promise<DeletionReplayResult>((resolve) => {
      finish = resolve;
    });
    const running = gate.reconcileBeforeServing(() => blocked);
    await Promise.resolve('completed' as const);
    expect(gate.state).toBe('recovering');
    expect(() => gate.assertApplicationReady()).toThrow('NOT_READY');
    await expect(
      gate.reconcileBeforeServing(() => Promise.resolve('completed' as const)),
    ).rejects.toThrow('ALREADY_RUNNING');
    finish('completed');
    await running;
    expect(gate.state).toBe('ready');
    gate.invalidate();
    expect(gate.state).toBe('closed');
    expect(() => gate.assertDeletionReady()).toThrow('NOT_READY');
  });
});
