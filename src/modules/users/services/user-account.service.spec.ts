import { BadRequestException, Logger } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { DataSource, DeepPartial, FindOneOptions, Repository } from 'typeorm';
import { MailService } from '../../../services/mail/mail.service';
import { CreateUserDto } from '../dto/create-user.dto';
import { User } from '../entities/user.entity';
import { UserAccountService } from './user-account.service';

type ReaderStub = {
  findOne: jest.Mock<Promise<User | null>, [FindOneOptions<User>]>;
};

type EditorStub = {
  create: jest.Mock<User, [DeepPartial<User>]>;
  save: jest.Mock<Promise<User>, [User]>;
  delete: jest.Mock<Promise<{ affected: number }>, [{ email: string }]>;
};

type MailStub = {
  sendVerificationEmail: jest.Mock<Promise<void>, [string, string, string]>;
};

const passwordHasher = bcrypt as {
  compare(password: string, hash: string): Promise<boolean>;
};

const normalizedEmail = 'cliente@example.test';
const mailFailureMessage =
  'Revisa que tu información sea correcta. Intenta de nuevo 1.';

function registration(): CreateUserDto {
  return {
    nombre: 'María',
    aPaterno: 'López',
    aMaterno: 'Pérez',
    email: ' CLIENTE@EXAMPLE.TEST ',
    telefono: '5512345678',
    passw: 'PruebaSegura!47',
  };
}

function storedUser(data: DeepPartial<User> = {}): User {
  return Object.assign(
    new User(),
    {
      id_usuario: 0,
      google_id: 'identificador-interno-del-proveedor',
      telefono_verified: 0,
      ubicacion: 17,
      fecha_actualizacion: new Date(),
    },
    data,
  );
}

describe('UserAccountService: respuesta pública del registro', () => {
  let reader: ReaderStub;
  let editor: EditorStub;
  let mail: MailStub;
  let service: UserAccountService;

  beforeEach(() => {
    reader = {
      findOne: jest
        .fn<Promise<User | null>, [FindOneOptions<User>]>()
        .mockResolvedValue(null),
    };
    editor = {
      create: jest
        .fn<User, [DeepPartial<User>]>()
        .mockImplementation((data) => storedUser(data)),
      save: jest.fn<Promise<User>, [User]>().mockImplementation((user) => {
        user.id_usuario = 42;
        return Promise.resolve(user);
      }),
      delete: jest
        .fn<Promise<{ affected: number }>, [{ email: string }]>()
        .mockResolvedValue({ affected: 1 }),
    };
    mail = {
      sendVerificationEmail: jest
        .fn<Promise<void>, [string, string, string]>()
        .mockResolvedValue(undefined),
    };
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    service = new UserAccountService(
      {} as DataSource,
      {} as DataSource,
      editor as unknown as Repository<User>,
      reader as unknown as Repository<User>,
      mail as unknown as MailService,
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('devuelve únicamente el identificador y el correo normalizado', async () => {
    const response = await service.createUser(registration());

    expect(response).toStrictEqual({
      id_usuario: 42,
      email: normalizedEmail,
    });
    expect(mail.sendVerificationEmail).toHaveBeenCalledTimes(1);
    expect(editor.delete).not.toHaveBeenCalled();
  });

  it('guarda el hash y el código de verificación y envía el código por correo', async () => {
    const input = registration();
    const startedAt = Date.now();

    const response = await service.createUser(input);

    expect(editor.save).toHaveBeenCalledTimes(1);
    const saved = editor.save.mock.calls[0][0];
    expect(saved.email).toBe(normalizedEmail);
    expect(saved.passw).not.toBe(input.passw);
    expect(await passwordHasher.compare(input.passw, saved.passw)).toBe(true);
    expect(saved.token_verificacion).toMatch(/^\d{6}$/);
    expect(saved.token_expiracion).toBeInstanceOf(Date);
    expect(saved.token_expiracion!.getTime()).toBeGreaterThan(startedAt);
    expect(saved).toMatchObject({
      email_verified: 0,
      activo: 0,
      rol: 1,
      intentos_token: 3,
    });
    expect(mail.sendVerificationEmail).toHaveBeenCalledWith(
      normalizedEmail,
      input.nombre,
      saved.token_verificacion,
    );
    expect(response).toStrictEqual({ id_usuario: 42, email: normalizedEmail });
    expect(input.passw).toBe('PruebaSegura!47');
  });

  it.each(['email', 'telefono'] as const)(
    'rechaza un %s duplicado sin guardar ni enviar correo',
    async (field) => {
      const input = registration();
      const existing = storedUser({ id_usuario: 7 });
      if (field === 'telefono') {
        reader.findOne.mockResolvedValueOnce(null);
      }
      reader.findOne.mockResolvedValueOnce(existing);

      await expect(service.createUser(input)).rejects.toBeInstanceOf(
        BadRequestException,
      );

      expect(reader.findOne).toHaveBeenCalledWith({
        where: {
          [field]: field === 'email' ? normalizedEmail : input.telefono,
        },
      });
      expect(editor.create).not.toHaveBeenCalled();
      expect(editor.save).not.toHaveBeenCalled();
      expect(editor.delete).not.toHaveBeenCalled();
      expect(mail.sendVerificationEmail).not.toHaveBeenCalled();
    },
  );

  it('revierte el registro si falla el correo sin exponer el error del proveedor', async () => {
    const providerDetail = 'SMTP_AUTH: credencial-interna-del-proveedor';
    mail.sendVerificationEmail.mockRejectedValueOnce(new Error(providerDetail));

    const result: unknown = await service
      .createUser(registration())
      .catch((error: unknown) => error);

    expect(result).toBeInstanceOf(BadRequestException);
    if (!(result instanceof BadRequestException)) {
      throw new Error(
        'Se esperaba el rechazo del registro por fallo del correo',
      );
    }
    expect(result.getStatus()).toBe(400);
    expect(result.getResponse()).toStrictEqual({
      statusCode: 400,
      error: 'Bad Request',
      message: mailFailureMessage,
    });
    expect(JSON.stringify(result.getResponse())).not.toContain(providerDetail);
    expect(editor.save).toHaveBeenCalledTimes(1);
    expect(mail.sendVerificationEmail).toHaveBeenCalledTimes(1);
    expect(editor.delete).toHaveBeenCalledTimes(1);
    expect(editor.delete).toHaveBeenCalledWith({ email: normalizedEmail });
  });
});
