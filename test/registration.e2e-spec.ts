import type { Server } from 'node:http';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { getDataSourceToken, getRepositoryToken } from '@nestjs/typeorm';
import request from 'supertest';
import { DeepPartial, EntityManager, FindOneOptions } from 'typeorm';
import { CreateUserResponseDto } from '../src/modules/users/dto/create-user-response.dto';
import { User } from '../src/modules/users/entities/user.entity';
import { UserAccountService } from '../src/modules/users/services/user-account.service';
import { UserAdminService } from '../src/modules/users/services/user-admin.service';
import { UserGoogleAuthService } from '../src/modules/users/services/user-google-auth.service';
import { UserPasswordRecoveryService } from '../src/modules/users/services/user-password-recovery.service';
import { UserSessionService } from '../src/modules/users/services/user-session.service';
import { UsersController } from '../src/modules/users/users.controller';
import { UsersService } from '../src/modules/users/users.service';
import { MailService } from '../src/services/mail/mail.service';
import { AccountDeletionAccessService } from '../src/modules/account-deletion/account-deletion-access.service';

function createDependencies() {
  let storedUser: User | undefined;
  const mail: jest.Mocked<
    Pick<MailService, 'sendVerificationEmail' | 'resendVerificationEmail'>
  > = {
    sendVerificationEmail: jest.fn(),
    resendVerificationEmail: jest.fn(),
  };
  mail.sendVerificationEmail.mockResolvedValue(undefined);
  mail.resendVerificationEmail.mockResolvedValue(undefined);

  const reader = {
    findOne: jest.fn((options: FindOneOptions<User>) => {
      const where = options.where;
      if (!storedUser || !where || Array.isArray(where)) {
        return Promise.resolve(null);
      }
      const matches =
        where.id_usuario === storedUser.id_usuario ||
        where.email === storedUser.email ||
        where.telefono === storedUser.telefono;
      return Promise.resolve(matches ? storedUser : null);
    }),
  };
  const editor = {
    create: jest.fn((values: DeepPartial<User>) =>
      Object.assign(new User(), values),
    ),
    save: jest.fn((user: User) => {
      user.id_usuario ||= 101;
      storedUser = user;
      return Promise.resolve(user);
    }),
    delete: jest.fn(() => {
      storedUser = undefined;
      return Promise.resolve({ affected: 1, raw: [] });
    }),
  };
  return { reader, editor, mail, getStoredUser: () => storedUser };
}

describe('Registro: contrato HTTP y verificación (dependencias aisladas)', () => {
  let app: INestApplication<Server>;
  let dependencies: ReturnType<typeof createDependencies>;
  const payload = {
    nombre: 'Cliente',
    aPaterno: 'Prueba',
    aMaterno: 'Registro',
    email: 'Registro@Example.test',
    telefono: '7710000001',
    passw: 'RegistroSeguro!2026',
  };

  beforeEach(async () => {
    dependencies = createDependencies();
    const module = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        UsersService,
        UserAccountService,
        {
          provide: AccountDeletionAccessService,
          useValue: {
            assertAllowed: jest.fn().mockResolvedValue(undefined),
            invalidateChallenges: jest.fn().mockResolvedValue(undefined),
            withAccountLock: async (
              _id: number,
              work: (manager: EntityManager, user: User) => Promise<unknown>,
            ) => {
              const user = dependencies.getStoredUser();
              if (!user) throw new Error('Missing isolated account fixture');
              return work(
                {
                  getRepository: () => dependencies.editor,
                } as unknown as EntityManager,
                user,
              );
            },
          },
        },
        { provide: UserSessionService, useValue: {} },
        { provide: UserPasswordRecoveryService, useValue: {} },
        { provide: UserGoogleAuthService, useValue: {} },
        { provide: UserAdminService, useValue: {} },
        { provide: getDataSourceToken('readerConnection'), useValue: {} },
        { provide: getDataSourceToken('editorConnection'), useValue: {} },
        {
          provide: getRepositoryToken(User, 'readerConnection'),
          useValue: dependencies.reader,
        },
        {
          provide: getRepositoryToken(User, 'editorConnection'),
          useValue: dependencies.editor,
        },
        { provide: MailService, useValue: dependencies.mail },
      ],
    }).compile();
    app = module.createNestApplication<INestApplication<Server>>();
    app.useLogger(false);
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    await app.init();
  });

  afterEach(async () => {
    if (app) await app.close();
  });

  it('devuelve 201 y únicamente id_usuario y email, sin campos internos', async () => {
    const response = await request(app.getHttpServer())
      .post('/users/create-user')
      .send(payload)
      .expect(201);

    expect(response.body as unknown).toEqual({
      id_usuario: 101,
      email: 'registro@example.test',
    });
    const storedUser = dependencies.getStoredUser();
    expect(storedUser).toBeDefined();
    expect(response.text).not.toContain(payload.passw);
    expect(response.text).not.toContain(storedUser!.passw);
    expect(response.text).not.toContain(storedUser!.token_verificacion);
    expect(dependencies.mail.sendVerificationEmail).toHaveBeenCalledWith(
      'registro@example.test',
      payload.nombre,
      storedUser!.token_verificacion,
    );
  });

  it('conserva registro, reenvío, rechazo de código incorrecto y verificación', async () => {
    const registered = await request(app.getHttpServer())
      .post('/users/create-user')
      .send(payload)
      .expect(201);
    const receipt = registered.body as CreateUserResponseDto;

    const resent = await request(app.getHttpServer())
      .post('/users/resend-code')
      .send({ email: receipt.email })
      .expect(201);
    expect(resent.body as unknown).toEqual({
      message: 'Codigo enviado correctamente. Revise su bandeja de entrada.',
    });
    expect(dependencies.mail.resendVerificationEmail).toHaveBeenCalledTimes(1);
    const code = dependencies.mail.resendVerificationEmail.mock.calls[0][2];
    expect(code).toMatch(/^\d{6}$/);

    await request(app.getHttpServer())
      .post('/users/verify-email')
      .send({
        email: receipt.email,
        token: code === '111111' ? '222222' : '111111',
      })
      .expect(400);
    expect(dependencies.getStoredUser()!.email_verified).toBe(0);

    const verified = await request(app.getHttpServer())
      .post('/users/verify-email')
      .send({ email: receipt.email, token: code })
      .expect(201);
    expect(verified.body as unknown).toEqual({
      message: 'Cuenta verificada correctamente.',
    });
    expect(dependencies.getStoredUser()).toMatchObject({
      email_verified: 1,
      activo: 1,
    });
  });

  it('rechaza un registro duplicado sin volver a guardar ni enviar correo', async () => {
    await request(app.getHttpServer())
      .post('/users/create-user')
      .send(payload)
      .expect(201);
    const response = await request(app.getHttpServer())
      .post('/users/create-user')
      .send(payload)
      .expect(400);
    expect(response.body as unknown).toEqual({
      statusCode: 400,
      error: 'Bad Request',
      message: 'Revisa que tu información sea correcta. Intenta de nuevo',
    });
    expect(dependencies.editor.save).toHaveBeenCalledTimes(1);
    expect(dependencies.mail.sendVerificationEmail).toHaveBeenCalledTimes(1);
  });

  it('oculta detalles del proveedor de correo y revierte el registro fallido', async () => {
    const providerDetail = 'smtp.example.invalid: ONLY_TEST_PROVIDER_DETAIL';
    dependencies.mail.sendVerificationEmail.mockRejectedValueOnce(
      new Error(providerDetail),
    );
    const response = await request(app.getHttpServer())
      .post('/users/create-user')
      .send(payload)
      .expect(400);

    expect(response.body as unknown).toEqual({
      statusCode: 400,
      error: 'Bad Request',
      message: 'Revisa que tu información sea correcta. Intenta de nuevo 1.',
    });
    expect(response.text).not.toContain(providerDetail);
    expect(response.text).not.toContain('smtp.example.invalid');
    expect(dependencies.editor.delete).toHaveBeenCalledWith({
      email: 'registro@example.test',
    });
    expect(dependencies.getStoredUser()).toBeUndefined();
  });
});
