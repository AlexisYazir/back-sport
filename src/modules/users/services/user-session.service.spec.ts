import {
  BadRequestException,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import {
  DataSource,
  DeepPartial,
  EntityManager,
  FindOneOptions,
  Repository,
} from 'typeorm';
import { AccountDeletionAccessService } from '../../account-deletion/account-deletion-access.service';
import { User } from '../entities/user.entity';
import { UserSession } from '../entities/user-session.entity';
import { Roles } from '../entities/roles.entity';
import { MailService } from '../../../services/mail/mail.service';
import { JwtStrategy } from '../../../services/auth/jwt.strategy';
import { UsersService } from '../users.service';
import { UserAccountService } from './user-account.service';
import { UserAdminService } from './user-admin.service';
import { UserGoogleAuthService } from './user-google-auth.service';
import { UserPasswordRecoveryService } from './user-password-recovery.service';
import { UserSessionService } from './user-session.service';

const passwordHasher = bcrypt as {
  hash(value: string, rounds: number): Promise<string>;
  compare(value: string, hash: string): Promise<boolean>;
};

const password = 'ClienteSeguro!2026';
const sessionId = '00000000-0000-4000-8000-000000000042';
const accessSecret = 'isolated-access-secret-never-a-real-credential';
const refreshSecret = 'isolated-refresh-secret-never-a-real-credential';
const context = {
  ipAddress: null,
  userAgent: 'isolated-test',
  deviceName: 'QA',
};
let passwordHash: string;
let wrongRefreshHash: string;

beforeAll(async () => {
  passwordHash = await passwordHasher.hash(password, 4);
  wrongRefreshHash = await passwordHasher.hash('different-isolated-refresh', 4);
});

function dependencies() {
  const originalUser = Object.assign(new User(), {
    id_usuario: 42,
    nombre: 'Cliente',
    aPaterno: 'Prueba',
    aMaterno: '',
    email: 'cliente@example.test',
    telefono: '7710000001',
    passw: passwordHash,
    activo: 1,
    email_verified: 1,
    rol: 1,
    google_id: 'google-account',
    token_verificacion: '123456',
    token_expiracion: new Date(Date.now() + 60000),
    intentos_token: 3,
  });
  const currentUser = Object.assign(new User(), originalUser);
  const reader = {
    findOne: jest.fn((options: FindOneOptions<User>) => {
      const where = options.where;
      const match =
        where &&
        !Array.isArray(where) &&
        (where.id_usuario === originalUser.id_usuario ||
          where.email === originalUser.email);
      return Promise.resolve(match ? originalUser : null);
    }),
  };
  const editor = {
    create: jest.fn((input: DeepPartial<User>) =>
      Object.assign(new User(), input, { id_usuario: 43 }),
    ),
    save: jest.fn((user: User) => Promise.resolve(user)),
    delete: jest.fn().mockResolvedValue({ affected: 1 }),
  };
  const lockedUsers = {
    save: jest.fn((user: User) => Promise.resolve(user)),
    delete: jest.fn().mockResolvedValue({ affected: 1 }),
  };
  const session: UserSession = Object.assign(new UserSession(), {
    id_sesion: sessionId,
    id_usuario: 42,
    revocada_en: null,
    expira_en: new Date(Date.now() + 60000),
    refresh_token_hash: wrongRefreshHash,
  });
  const lockedSessions = {
    findOne: jest.fn().mockImplementation(() => Promise.resolve(session)),
    find: jest.fn().mockResolvedValue([]),
    create: jest.fn((input: DeepPartial<UserSession>) =>
      Object.assign(new UserSession(), input),
    ),
    save: jest.fn((input: UserSession) => Promise.resolve(input)),
  };
  const legacySessions = {
    findOne: jest.fn().mockImplementation(() => Promise.resolve(session)),
    find: jest.fn().mockResolvedValue([]),
    create: jest.fn(),
    save: jest.fn(),
  };
  const query = jest
    .fn<Promise<unknown[]>, [string, unknown[]?]>()
    .mockResolvedValue([]);
  const manager = {
    query,
    getRepository: (entity: typeof User | typeof UserSession) =>
      entity === User ? lockedUsers : lockedSessions,
  } as unknown as EntityManager;
  const state = { blocked: false, commits: 0 };
  const access = {
    assertAllowed: jest.fn(() => {
      if (state.blocked) throw new ForbiddenException('Cuenta en eliminación');
      return Promise.resolve();
    }),
    withAccountLock: jest.fn(
      async (
        _id: number,
        work: (manager: EntityManager, user: User) => Promise<unknown>,
        transactionManager?: EntityManager,
      ) => {
        if (state.blocked)
          throw new ForbiddenException('Cuenta en eliminación');
        const result = await work(transactionManager ?? manager, currentUser);
        state.commits += 1;
        return result;
      },
    ),
    invalidateChallenges: jest.fn().mockResolvedValue(undefined),
  };
  const config = {
    getOrThrow: (key: string) =>
      key === 'JWT_SECRET' ? accessSecret : refreshSecret,
    get: () => 'isolated-google-client-id',
  } as unknown as ConfigService;
  const mail = {
    sendVerificationEmail: jest.fn().mockResolvedValue(undefined),
    resendVerificationEmail: jest.fn().mockResolvedValue(undefined),
    sendRecoveryEmail: jest.fn().mockResolvedValue(undefined),
    requestVerificationCodeLogin: jest.fn().mockResolvedValue(undefined),
  };
  const readerDataSource = {
    query: jest.fn().mockResolvedValue([]),
  } as unknown as DataSource;
  const accessService = access as unknown as AccountDeletionAccessService;
  const sessions = new UserSessionService(
    reader as unknown as Repository<User>,
    legacySessions as unknown as Repository<UserSession>,
    legacySessions as unknown as Repository<UserSession>,
    config,
    accessService,
  );
  const account = new UserAccountService(
    readerDataSource,
    {} as DataSource,
    editor as unknown as Repository<User>,
    reader as unknown as Repository<User>,
    mail as unknown as MailService,
    accessService,
  );
  const recovery = new UserPasswordRecoveryService(
    editor as unknown as Repository<User>,
    reader as unknown as Repository<User>,
    mail as unknown as MailService,
    accessService,
  );
  const adminRepository = Object.assign(editor, { manager });
  const admin = new UserAdminService(
    reader as unknown as Repository<User>,
    adminRepository as unknown as Repository<User>,
    {} as Repository<Roles>,
    accessService,
  );
  return {
    originalUser,
    currentUser,
    reader,
    editor,
    lockedUsers,
    session,
    lockedSessions,
    legacySessions,
    manager,
    query,
    state,
    access,
    accessService,
    config,
    mail,
    readerDataSource,
    sessions,
    account,
    recovery,
    admin,
  };
}

describe('Account deletion: existing authentication and profile integration', () => {
  it('issues normal login tokens using the account-locked manager', async () => {
    const d = dependencies();
    const result = await d.sessions.loginUser(
      d.originalUser.email,
      password,
      context,
    );
    expect(jwt.verify(result.accessToken, accessSecret)).toMatchObject({
      id_usuario: 42,
    });
    expect(d.access.withAccountLock).toHaveBeenCalledWith(
      42,
      expect.any(Function),
      undefined,
    );
    expect(d.lockedSessions.save).toHaveBeenCalledTimes(1);
    expect(d.legacySessions.save).not.toHaveBeenCalled();
  });

  it('does not issue a session when deletion started after the credential lookup', async () => {
    const d = dependencies();
    d.state.blocked = true;
    await expect(
      d.sessions.loginUser(d.originalUser.email, password, context),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(d.lockedSessions.save).not.toHaveBeenCalled();
  });

  it('does not issue tokens from an identity snapshot changed before the lock', async () => {
    const d = dependencies();
    d.currentUser.email = 'nuevo@example.test';
    await expect(
      d.sessions.issueSessionTokensForUser(d.originalUser, context),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(d.lockedSessions.save).not.toHaveBeenCalled();
  });

  it.each(['refresh', 'restore'] as const)(
    'rejects %s during deletion without persisting a session',
    async (kind) => {
      const d = dependencies();
      d.state.blocked = true;
      const token = jwt.sign(
        { id_usuario: 42, sessionId },
        kind === 'refresh' ? refreshSecret : accessSecret,
      );
      const work =
        kind === 'refresh'
          ? d.sessions.refreshToken(token, context)
          : d.sessions.restoreSessionFromAccessToken(token, context);
      await expect(work).rejects.toBeInstanceOf(UnauthorizedException);
      expect(d.lockedSessions.save).not.toHaveBeenCalled();
    },
  );

  it('rechecks the current session under the lock before restoring access', async () => {
    const d = dependencies();
    d.session.revocada_en = new Date();
    const token = jwt.sign({ id_usuario: 42, sessionId }, accessSecret);
    await expect(
      d.sessions.restoreSessionFromAccessToken(token, context),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(d.lockedSessions.save).not.toHaveBeenCalled();
  });

  it('commits refresh-token mismatch revocation before rejecting it', async () => {
    const d = dependencies();
    const token = jwt.sign({ id_usuario: 42, sessionId }, refreshSecret);
    await expect(
      d.sessions.refreshToken(token, context),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(d.lockedSessions.save).toHaveBeenCalledWith(
      expect.objectContaining({ motivo_revocacion: 'refresh_token_mismatch' }),
    );
    expect(d.state.commits).toBe(1);
  });

  it('preserves valid refresh and its existing session identifier', async () => {
    const d = dependencies();
    const token = jwt.sign({ id_usuario: 42, sessionId }, refreshSecret);
    d.session.refresh_token_hash = await passwordHasher.hash(token, 4);
    const result = await d.sessions.refreshToken(token, context);
    expect(result.sessionId).toBe(sessionId);
    expect(jwt.verify(result.accessToken, accessSecret)).toMatchObject({
      id_usuario: 42,
      sessionId,
    });
    expect(d.lockedSessions.save).toHaveBeenCalledTimes(1);
  });

  it('does not restore a previously read session row through logout during deletion', async () => {
    const d = dependencies();
    d.state.blocked = true;
    await expect(d.sessions.logout(sessionId)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    expect(d.lockedSessions.save).not.toHaveBeenCalled();
    expect(d.legacySessions.save).not.toHaveBeenCalled();
  });

  it('rejects an otherwise active JWT when the account is deleting', async () => {
    const d = dependencies();
    d.state.blocked = true;
    const users = { isSessionActive: jest.fn().mockResolvedValue(true) };
    const strategy = new JwtStrategy(
      d.config,
      users as unknown as UsersService,
      d.accessService,
    );
    await expect(
      strategy.validate({ sessionId, id_usuario: 42 }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(users.isSessionActive).not.toHaveBeenCalled();
  });

  it('keeps the existing valid JWT payload contract', async () => {
    const d = dependencies();
    const users = { isSessionActive: jest.fn().mockResolvedValue(true) };
    const strategy = new JwtStrategy(
      d.config,
      users as unknown as UsersService,
      d.accessService,
    );
    const payload = {
      sessionId,
      id_usuario: 42,
      email: d.currentUser.email,
      nombre: 'Cliente',
      rol: 1,
    };
    await expect(strategy.validate(payload)).resolves.toEqual(payload);
  });

  it('invalidates deletion challenges and email verification when the profile email changes', async () => {
    const d = dependencies();
    const result = await d.account.updateUserProfile(42, {
      email: ' NUEVO@EXAMPLE.TEST ',
    });
    expect(result.user).toMatchObject({
      email: 'nuevo@example.test',
      email_verified: 0,
      token_verificacion: '',
      token_expiracion: null,
    });
    expect(d.access.invalidateChallenges).toHaveBeenCalledWith(42, d.manager);
    expect(d.lockedUsers.save).toHaveBeenCalledTimes(1);
    expect(d.mail.sendVerificationEmail).not.toHaveBeenCalled();
  });

  it('preserves verified email and the normal profile result for unrelated edits', async () => {
    const d = dependencies();
    const result = await d.account.updateUserProfile(42, {
      nombre: 'Nuevo nombre',
    });
    expect(result.user).toMatchObject({
      nombre: 'Nuevo nombre',
      email_verified: 1,
    });
    expect(result.user).not.toHaveProperty('passw');
    expect(d.access.invalidateChallenges).not.toHaveBeenCalled();
  });

  it('does not accept a deletion email anchor or verification status from profile input', async () => {
    const d = dependencies();
    const input = {
      email: 'nuevo@example.test',
      identity_email: 'correo-no-autorizado@example.test',
      email_verified: 1,
    };
    await d.account.updateUserProfile(42, input);
    expect(d.currentUser.email).toBe('nuevo@example.test');
    expect(d.currentUser.email_verified).toBe(0);
    expect(d.currentUser).not.toHaveProperty('identity_email');
    expect(d.query).not.toHaveBeenCalled();
    expect(d.access.invalidateChallenges).toHaveBeenCalledWith(42, d.manager);
  });

  it('does not reactivate a deleting account through email verification', async () => {
    const d = dependencies();
    d.state.blocked = true;
    await expect(
      d.account.verifyEmail(d.originalUser.email, '123456'),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(d.lockedUsers.save).not.toHaveBeenCalled();
  });

  it.each([
    'profile',
    'alexa',
    'recovery',
    'reset',
    'adminRestore',
    'adminDelete',
  ] as const)(
    'blocks %s before an account mutation or email during deletion',
    async (operation) => {
      const d = dependencies();
      d.state.blocked = true;
      const work = {
        profile: () => d.account.updateUserProfile(42, { nombre: 'Otro' }),
        alexa: () => d.account.requestAlexaVerificationCode(42),
        recovery: () => d.recovery.verifyUserEmail(d.originalUser.email),
        reset: () =>
          d.recovery.resetPsw(
            d.originalUser.email,
            'OtraClaveSegura!2026',
            '123456',
          ),
        adminRestore: () =>
          d.admin.updateUserStatus({ id_usuario: 42, activo: 1 }),
        adminDelete: () => d.admin.deleteUser(42),
      }[operation];
      await expect(work()).rejects.toBeInstanceOf(ForbiddenException);
      expect(d.lockedUsers.save).not.toHaveBeenCalled();
      expect(d.lockedUsers.delete).not.toHaveBeenCalled();
      expect(d.query).not.toHaveBeenCalled();
      expect(d.mail.sendRecoveryEmail).not.toHaveBeenCalled();
      expect(d.mail.requestVerificationCodeLogin).not.toHaveBeenCalled();
    },
  );

  it('commits an incorrect recovery-code attempt before returning its validation error', async () => {
    const d = dependencies();
    await expect(
      d.recovery.verifyUserToken(d.originalUser.email, '654321'),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(d.lockedUsers.save).toHaveBeenCalledWith(
      expect.objectContaining({ intentos_token: 2 }),
    );
    expect(d.state.commits).toBe(1);
  });

  it('preserves recovery email delivery for a normal active account', async () => {
    const d = dependencies();
    const result = await d.recovery.verifyUserEmail(d.currentUser.email);
    expect(result.message).toBe(
      'Correo de recuperación enviado correctamente.',
    );
    expect(d.mail.sendRecoveryEmail).toHaveBeenCalledWith(
      d.currentUser.email,
      d.currentUser.nombre,
      expect.stringMatching(/^\d{6}$/),
    );
    expect(d.lockedUsers.save).toHaveBeenCalledTimes(1);
  });

  it('preserves a valid password reset without reviving identity fields', async () => {
    const d = dependencies();
    const result = await d.recovery.resetPsw(
      d.currentUser.email,
      'OtraClaveSegura!2026',
      '123456',
    );
    expect(result.message).toBe('Contraseña actualizada correctamente.');
    expect(
      await passwordHasher.compare('OtraClaveSegura!2026', d.currentUser.passw),
    ).toBe(true);
    expect(d.currentUser.email).toBe(d.originalUser.email);
    expect(d.currentUser.token_verificacion).toBe('');
  });

  it('does not exchange a previously located Alexa code while deletion is in progress', async () => {
    const d = dependencies();
    d.state.blocked = true;
    jest
      .spyOn(d.readerDataSource, 'query')
      .mockImplementation((sql: string) =>
        Promise.resolve(
          sql.includes('SELECT id_usuario FROM core.alexa_codes')
            ? [{ id_usuario: 42 }]
            : [],
        ),
      );
    await expect(
      d.account.verifyAlexaVerificationCode('123456', 'isolated-alexa-user'),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(d.query).not.toHaveBeenCalled();
    expect(d.lockedUsers.save).not.toHaveBeenCalled();
  });

  it('keeps active administrator updates on their original manager', async () => {
    const d = dependencies();
    await expect(
      d.admin.updateUserStatus({ id_usuario: 42, activo: 0 }),
    ).resolves.toMatchObject({ activo: 0 });
    expect(d.access.withAccountLock).toHaveBeenCalledWith(
      42,
      expect.any(Function),
      d.manager,
    );
    expect(d.lockedUsers.save).toHaveBeenCalledTimes(1);
  });
});

describe('Account deletion: Google sign-in integration', () => {
  const identity = {
    email: 'cliente@example.test',
    name: 'Cliente',
    aPaterno: 'Prueba',
    aMaterno: '',
    googleId: 'google-account',
    email_verified: true,
  };

  function google(d: ReturnType<typeof dependencies>) {
    const issue = jest
      .fn()
      .mockResolvedValue({ accessToken: 'isolated-access' });
    const service = new UserGoogleAuthService(
      d.editor as unknown as Repository<User>,
      d.reader as unknown as Repository<User>,
      d.config,
      { issueSessionTokensForUser: issue } as unknown as UserSessionService,
      d.accessService,
    );
    jest
      .spyOn(
        service as unknown as {
          verifyGoogleToken: () => Promise<typeof identity>;
        },
        'verifyGoogleToken',
      )
      .mockResolvedValue(identity);
    return { service, issue };
  }

  it('does not let Google reactivate the previous account during deletion', async () => {
    const d = dependencies();
    d.state.blocked = true;
    const g = google(d);
    await expect(
      g.service.loginWithGoogle('isolated-token', context),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(d.lockedUsers.save).not.toHaveBeenCalled();
    expect(g.issue).not.toHaveBeenCalled();
  });

  it('preserves normal Google sign-in and passes its locked transaction to session issuance', async () => {
    const d = dependencies();
    const g = google(d);
    await expect(
      g.service.loginWithGoogle('isolated-token', context),
    ).resolves.toEqual({ accessToken: 'isolated-access' });
    expect(d.lockedUsers.save).toHaveBeenCalledWith(
      expect.objectContaining({ google_id: identity.googleId, activo: 1 }),
    );
    expect(g.issue).toHaveBeenCalledWith(d.currentUser, context, d.manager);
  });
});
