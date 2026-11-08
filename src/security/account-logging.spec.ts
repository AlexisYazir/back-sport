import { BadRequestException, Logger } from '@nestjs/common';
import { DataSource, Repository } from 'typeorm';
import { UserAccountService } from '../modules/users/services/user-account.service';
import { UserAdminService } from '../modules/users/services/user-admin.service';
import { User } from '../modules/users/entities/user.entity';
import { Roles } from '../modules/users/entities/roles.entity';
import { MailService } from '../services/mail/mail.service';
import { AccountDeletionAccessService } from '../modules/account-deletion/account-deletion-access.service';

describe('Account logging keeps profile data and provider errors private', () => {
  afterEach(() => jest.restoreAllMocks());
  it('returns the same profile without logging it, its ID or personal fields', async () => {
    const log = jest
      .spyOn(Logger.prototype, 'log')
      .mockImplementation(() => undefined);
    const profile = Object.assign(new User(), {
      nombre: 'CANARY_NAME_SECRET',
      email: 'canary@example.test',
      telefono: '5550000000',
    });
    const reader = { findOne: jest.fn().mockResolvedValue(profile) };
    const service = new UserAccountService(
      {} as DataSource,
      {} as DataSource,
      {} as Repository<User>,
      reader as unknown as Repository<User>,
      {} as MailService,
      {
        assertAllowed: jest.fn().mockResolvedValue(undefined),
      } as unknown as AccountDeletionAccessService,
    );
    await expect(service.getProfile(42)).resolves.toBe(profile);
    reader.findOne.mockResolvedValue(null);
    await expect(service.getProfile(43)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(service.getProfile(0)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(log).not.toHaveBeenCalled();
  });
  it('rethrows a query failure unchanged while logging a static event', async () => {
    const log = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const original = new Error('CANARY_DATABASE_ERROR_SECRET');
    const reader = { query: jest.fn().mockRejectedValue(original) };
    const service = new UserAdminService(
      reader as unknown as Repository<User>,
      {} as Repository<User>,
      {} as Repository<Roles>,
      {} as AccountDeletionAccessService,
    );
    await expect(service.getRecentUsersCreated()).rejects.toBe(original);
    expect(log).toHaveBeenCalledWith('Recent accounts query failed');
    expect(JSON.stringify(log.mock.calls)).not.toContain('CANARY_');
  });
});
