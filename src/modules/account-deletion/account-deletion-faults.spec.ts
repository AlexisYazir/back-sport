import { ConfigService } from '@nestjs/config';
import { ServiceUnavailableException } from '@nestjs/common';
import type { DataSource, EntityManager } from 'typeorm';
import type { MailService } from '../../services/mail/mail.service';
import { AccountDeletionService } from './account-deletion.service';
import type { AccountDeletionDataService } from './account-deletion-data.service';
import { DeletionSecrets } from './deletion-secrets';
import type { DeletionRecoveryGate } from './deletion-recovery-gate';
import type { DeletionLedger } from './ledger/deletion-ledger';

describe('Deletion confirmation failure boundary', () => {
  const requestId = '10000000-0000-4000-8000-000000000001';
  const sessionId = '20000000-0000-4000-8000-000000000001';
  const actor = { id_usuario: 1, sessionId, rol: 1 };
  function setup(commitFailure = false) {
    const config = new ConfigService({
      ACCOUNT_DELETION_ENABLED: 'true',
      ACCOUNT_DELETION_SECRET: 'ab'.repeat(32),
    });
    const crypto = new DeletionSecrets(config);
    const request = {
      request_id: requestId,
      user_id: 1,
      account_id: '30000000-0000-4000-8000-000000000001',
      session_id: sessionId,
      status: 'identity_verified',
      authorization_expires_at: new Date(Date.now() + 60_000),
      authorization_hash: crypto.hash(
        'authorization',
        requestId,
        'confirmation',
      ),
      email_hash: crypto.hash('email', requestId, 'owner@qa.invalid'),
    };
    const user = {
      id_usuario: 1,
      rol: 1,
      email: 'owner@qa.invalid',
      fecha_creacion: new Date('2026-01-01T00:00:00Z'),
    };
    const manager = {
      query: jest.fn((sql: string) => {
        if (sql.startsWith('SELECT state'))
          return Promise.resolve([{ state: 'active' }]);
        if (sql.startsWith('SELECT id_sesion'))
          return Promise.resolve([{ id_sesion: sessionId }]);
        if (sql.startsWith('SELECT identity_email'))
          return Promise.resolve([{ identity_email: 'owner@qa.invalid' }]);
        if (sql.startsWith('SELECT *')) return Promise.resolve([request]);
        return Promise.resolve([]);
      }),
      getRepository: () => ({ findBy: () => Promise.resolve([user]) }),
    };
    const source = {
      transaction: async (work: (m: EntityManager) => Promise<unknown>) => {
        const result = await work(manager as unknown as EntityManager);
        if (commitFailure) throw new Error('synthetic commit failure');
        return result;
      },
      query: jest.fn().mockResolvedValue([
        {
          ...request,
          status: 'completed',
          reason: null,
          retained_categories: [],
          notification_status: 'pending',
        },
      ]),
    };
    const ledger = {
      recordIntent: jest.fn().mockResolvedValue(undefined),
      recordRetention: jest.fn().mockResolvedValue(undefined),
      markCompleted: jest.fn(),
      verifyAndRead: jest.fn(),
    };
    const gate = {
      assertDeletionReady: jest.fn(),
      assertApplicationReady: jest.fn(),
      invalidate: jest.fn(),
      reconcileBeforeServing: jest
        .fn()
        .mockRejectedValue(new Error('unverifiable ledger')),
    };
    const service = new AccountDeletionService(
      source as unknown as DataSource,
      config,
      crypto,
      {} as AccountDeletionDataService,
      {} as MailService,
      ledger as DeletionLedger,
      gate as unknown as DeletionRecoveryGate,
    );
    return { service, ledger, gate, source, request };
  }
  test('a failed ledger append closes ordinary access and never declares completion', async () => {
    const { service, ledger, gate } = setup();
    ledger.recordIntent.mockRejectedValueOnce(
      new Error('checkpoint write failed'),
    );
    await expect(
      service.confirm(actor, requestId, 'confirmation', true),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(gate.invalidate).toHaveBeenCalledTimes(1);
    expect(gate.reconcileBeforeServing).toHaveBeenCalledTimes(1);
    expect(ledger.markCompleted).not.toHaveBeenCalled();
  });
  test('a database commit failure after a durable intent is reconciled before reporting a result', async () => {
    const { service, gate } = setup(true);
    gate.reconcileBeforeServing.mockResolvedValueOnce(undefined);
    const result = await service.confirm(
      actor,
      requestId,
      'confirmation',
      true,
    );
    expect(gate.invalidate).toHaveBeenCalledTimes(1);
    expect(result.status).toBe('completed');
  });
  test('cancelling or an invalid confirmation does not create an irreversible intent', async () => {
    const { service, ledger, gate } = setup();
    await expect(
      service.confirm(actor, requestId, 'confirmation', false),
    ).rejects.toThrow('confirmar');
    await expect(
      service.confirm(actor, requestId, 'incorrect', true),
    ).rejects.toThrow('ya no es válida');
    expect(ledger.recordIntent).not.toHaveBeenCalled();
    expect(gate.invalidate).not.toHaveBeenCalled();
  });
  test('an unverified recovery cannot report a previously cached result as current', async () => {
    const { service, gate, source } = setup();
    gate.assertApplicationReady.mockImplementationOnce(() => {
      throw new Error('closed');
    });
    await expect(service.result(requestId, 'receipt')).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    expect(source.query).not.toHaveBeenCalled();
  });
});
