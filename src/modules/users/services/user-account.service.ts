/* eslint-disable */
import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, EntityManager, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

import { MailService } from '../../../services/mail/mail.service';
import { CreateUserDto } from '../dto/create-user.dto';
import { CreateUserResponseDto } from '../dto/create-user-response.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { User } from '../entities/user.entity';
import { AccountDeletionAccessService } from '../../account-deletion/account-deletion-access.service';

@Injectable()
export class UserAccountService {
  private readonly logger = new Logger(UserAccountService.name);

  constructor(
    @InjectDataSource('readerConnection')
    private readonly readerDataSource: DataSource,
    @InjectDataSource('editorConnection')
    private readonly editorDataSource: DataSource,
    @InjectRepository(User, 'editorConnection')
    private readonly userEditorRepository: Repository<User>,
    @InjectRepository(User, 'readerConnection')
    private readonly userReaderRepository: Repository<User>,
    private readonly mailService: MailService,
    private readonly accountDeletionAccess: AccountDeletionAccessService,
  ) {}

  // Expected validation failures may update attempt counters. Commit those
  // changes before surfacing the error; unexpected failures still roll back.
  private async mutateAccount<T>(
    id: number,
    work: (manager: EntityManager, user: User) => Promise<T>,
  ): Promise<T> {
    const result = await this.accountDeletionAccess.withAccountLock<
      { ok: true; value: T } | { ok: false; error: BadRequestException }
    >(id, async (manager, user) => {
      try {
        return { ok: true, value: await work(manager, user) };
      } catch (error) {
        if (error instanceof BadRequestException) return { ok: false, error };
        throw error;
      }
    });
    if (!result.ok) throw result.error;
    return result.value;
  }

  async createUser(
    createUserDto: CreateUserDto,
  ): Promise<CreateUserResponseDto> {
    if (!createUserDto.email) {
      throw new BadRequestException('El correo es obligatorio');
    }
    const email = createUserDto.email.trim().toLowerCase();

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('El correo no tiene un formato válido');
    }

    const existingUser = await this.userReaderRepository.findOne({
      where: { email },
    });
    if (existingUser) {
      throw new BadRequestException(
        'Revisa que tu información sea correcta. Intenta de nuevo',
      );
    }

    if (!createUserDto.telefono) {
      throw new BadRequestException('El telefono es obligatorio');
    }

    const existingTelefono = await this.userReaderRepository.findOne({
      where: { telefono: createUserDto.telefono },
    });
    if (existingTelefono) {
      throw new BadRequestException(
        'Revisa que tu información sea correcta. Intenta de nuevo',
      );
    }

    if (!/^\d{10}$/.test(createUserDto.telefono)) {
      throw new BadRequestException(
        'El telefono debe tener exactamente 10 dígitos numéricos.',
      );
    }

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!#$%&¿?@*_/-])[A-Za-z\d!#$%&¿?@*_/-]{12,}$/;

    if (!passwordRegex.test(createUserDto.passw)) {
      throw new BadRequestException(
        'La contraseña debe tener mínimo 12 caracteres, una mayúscula, una minúscula, un número y un carácter especial (!#$%&¿?@*_-/), y sin recuencias(123)',
      );
    }
    const hashedPassword = await bcrypt.hash(createUserDto.passw, 10);

    const code = crypto.randomInt(100000, 1000000).toString();

    const expirationDate = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const newUser = this.userEditorRepository.create({
      ...createUserDto,
      email,
      passw: hashedPassword,
      email_verified: 0,
      intentos_token: 3,
      token_verificacion: code,
      token_expiracion: expirationDate,
      fecha_creacion: new Date(),
      activo: 0,
      rol: 1,
    });

    await this.userEditorRepository.save(newUser);

    try {
      await this.mailService.sendVerificationEmail(
        newUser.email,
        newUser.nombre,
        code,
      );
    } catch (error) {
      await this.userEditorRepository.delete({ email: newUser.email });
      this.logger.error('Account verification delivery failed');
      throw new BadRequestException(
        'Revisa que tu información sea correcta. Intenta de nuevo 1.',
      );
    }

    return {
      id_usuario: newUser.id_usuario,
      email: newUser.email,
    };
  }

  async verifyEmail(
    email: string,
    token: string,
  ): Promise<{ message: string }> {
    try {
      if (!email) {
        throw new BadRequestException('El correo es obligatorio');
      }

      if (!token) {
        throw new BadRequestException('El código es obligatorio');
      }

      if (token.length !== 6) {
        throw new BadRequestException('El código debe tener 6 dígitos');
      }

      const user = await this.userReaderRepository.findOne({
        where: { email },
      });

      if (!user) {
        throw new BadRequestException(
          'Revisa que tu información sea correcta. Intenta de nuevo',
        );
      }

      return this.mutateAccount(user.id_usuario, async (manager, user) => {
        if (user.email !== email)
          throw new BadRequestException(
            'La cuenta cambió. Solicita un nuevo código.',
          );
        const repository = manager.getRepository(User);
        const now = new Date();

        if (!user.token_expiracion || now > user.token_expiracion) {
          user.token_verificacion = '';
          user.token_expiracion = null;
          user.intentos_token = 0;
          await repository.save(user);

          throw new BadRequestException(
            'El token ha expirado, solicita uno nuevo.',
          );
        }

        if (
          typeof user.intentos_token !== 'number' ||
          user.intentos_token <= 0
        ) {
          user.token_verificacion = '';
          user.token_expiracion = null;
          user.intentos_token = 0;
          await repository.save(user);

          throw new BadRequestException(
            'Se han agotado los intentos. Solicita un nuevo token.',
          );
        }

        if (user.token_verificacion !== token) {
          user.intentos_token -= 1;
          await repository.save(user);

          if (user.intentos_token <= 0) {
            user.token_verificacion = '';
            user.token_expiracion = null;
            user.intentos_token = 0;
            await repository.save(user);

            throw new BadRequestException(
              'Has agotado los intentos. Solicita un nuevo token.',
            );
          }

          throw new BadRequestException(
            'El token es incorrecto' +
              '. Te quedan ' +
              user.intentos_token +
              ' intentos.',
          );
        }

        user.email_verified = 1;
        user.activo = 1;

        await repository.save(user);

        return { message: 'Cuenta verificada correctamente.' };
      });
    } catch (error) {
      throw error;
    }
  }

  async resendVerificationEmail(email: string): Promise<{ message: string }> {
    try {
      const emaill = email.trim().toLowerCase();

      if (!emaill) {
        throw new BadRequestException('El correo es obligatorio');
      }

      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(emaill)) {
        throw new BadRequestException('El correo no tiene un formato válido');
      }

      const existingUser = await this.userReaderRepository.findOne({
        where: { email: emaill },
      });

      if (!existingUser) {
        throw new BadRequestException(
          'Revisa que tu información sea correcta. Intenta de nuevo',
        );
      }
      return this.mutateAccount(
        existingUser.id_usuario,
        async (manager, existingUser) => {
          if (existingUser.email !== emaill)
            throw new BadRequestException(
              'La cuenta cambió. Solicita un nuevo código.',
            );
          const code = crypto.randomInt(100000, 1000000).toString();

          const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000);

          existingUser.token_verificacion = code;
          existingUser.token_expiracion = expiration;
          existingUser.intentos_token = 3;

          await manager.getRepository(User).save(existingUser);

          await this.mailService.resendVerificationEmail(
            existingUser.email,
            existingUser.nombre,
            code,
          );

          return {
            message:
              'Codigo enviado correctamente. Revise su bandeja de entrada.',
          };
        },
      );
    } catch (error) {
      throw error;
    }
  }

  async requestVerificationCode(email: string): Promise<{ message: string }> {
    try {
      const emaill = String(email || '')
        .trim()
        .toLowerCase();

      if (!emaill) {
        throw new BadRequestException('El correo es obligatorio');
      }

      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(emaill)) {
        throw new BadRequestException('El correo no tiene un formato válido');
      }

      const existingUser = await this.userReaderRepository.findOne({
        where: { email: emaill },
      });

      if (!existingUser) {
        throw new BadRequestException(
          'Revisa que tu información sea correcta. Intenta de nuevo',
        );
      }

      return this.mutateAccount(
        existingUser.id_usuario,
        async (manager, existingUser) => {
          if (existingUser.email !== emaill)
            throw new BadRequestException(
              'La cuenta cambió. Solicita un nuevo código.',
            );
          const code = crypto.randomInt(100000, 1000000).toString();
          const expiration = new Date(Date.now() + 15 * 60 * 1000);

          existingUser.token_verificacion = code;
          existingUser.token_expiracion = expiration;
          existingUser.intentos_token = 3;

          await manager.getRepository(User).save(existingUser);

          await this.mailService.requestVerificationCodeLogin(
            existingUser.email,
            existingUser.nombre,
            code,
            '15 minutos',
          );

          return {
            message:
              'Código de verificación enviado correctamente. Expira en 15 minutos.',
          };
        },
      );
    } catch (error) {
      throw error;
    }
  }

  async requestAlexaVerificationCode(id_usuario: number): Promise<{
    message: string;
    email: string;
    token: string | null;
    expiresAt: string | null;
    remainingSeconds: number;
    hasActiveCode: boolean;
    isLinked: boolean;
    linkedAt: string | null;
  }> {
    if (!Number.isInteger(Number(id_usuario)) || Number(id_usuario) <= 0) {
      throw new BadRequestException('Usuario no válido');
    }

    const user = await this.userReaderRepository.findOne({
      where: { id_usuario: Number(id_usuario) },
    });

    if (!user || !user.email) {
      throw new BadRequestException('Usuario no encontrado');
    }

    return this.mutateAccount(user.id_usuario, async (manager, user) => {
      const activeCode = await this.getActiveAlexaCodeForUser(user, manager);
      if (activeCode.hasActiveCode) {
        return {
          ...activeCode,
          message: 'Ya tienes un código de Alexa activo.',
        };
      }

      const code = crypto.randomInt(100000, 1000000).toString();
      const tokenHash = this.hashAlexaToken(code);

      await manager.query(
        `
      UPDATE core.alexa_codes
      SET used_at = CURRENT_TIMESTAMP,
          attempts = 0
      WHERE id_usuario = $1
        AND purpose = 'ALEXA'
        AND used_at IS NULL
        AND expires_at > CURRENT_TIMESTAMP;
      `,
        [user.id_usuario],
      );

      const insertedRows = await manager.query(
        `
      INSERT INTO core.alexa_codes (
        id_usuario,
        token_hash,
        purpose,
        expires_at,
        attempts,
        created_at
      )
      VALUES ($1, $2, 'ALEXA', CURRENT_TIMESTAMP + INTERVAL '5 minutes', 5, CURRENT_TIMESTAMP)
      RETURNING
        to_char(expires_at, 'YYYY-MM-DD"T"HH24:MI:SS.MS') || 'Z' AS expires_at,
        GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (expires_at - CURRENT_TIMESTAMP))))::int AS remaining_seconds;
      `,
        [user.id_usuario, tokenHash],
      );
      const inserted = insertedRows[0];

      await this.mailService.requestVerificationCodeLogin(
        user.email,
        user.nombre,
        code,
        '5 minutos',
      );

      const linkStatus = await this.getAlexaLinkStatusForUser(
        user.id_usuario,
        manager,
      );

      return {
        message: 'Código de Alexa generado correctamente. Expira en 5 minutos.',
        email: user.email,
        token: code,
        expiresAt: inserted?.expires_at || null,
        remainingSeconds: Number(inserted?.remaining_seconds || 0),
        hasActiveCode: true,
        ...linkStatus,
      };
    });
  }

  async getAlexaVerificationCode(id_usuario: number): Promise<{
    message: string;
    email: string;
    token: string | null;
    expiresAt: string | null;
    remainingSeconds: number;
    hasActiveCode: boolean;
    isLinked: boolean;
    linkedAt: string | null;
  }> {
    if (!Number.isInteger(Number(id_usuario)) || Number(id_usuario) <= 0) {
      throw new BadRequestException('Usuario no válido');
    }

    const user = await this.userReaderRepository.findOne({
      where: { id_usuario: Number(id_usuario) },
    });

    if (!user || !user.email) {
      throw new BadRequestException('Usuario no encontrado');
    }

    await this.accountDeletionAccess.assertAllowed(user.id_usuario);
    return this.getActiveAlexaCodeForUser(user);
  }

  async unlinkAlexaAccount(
    id_usuario: number,
  ): Promise<{ message: string; isLinked: boolean; linkedAt: string | null }> {
    if (!Number.isInteger(Number(id_usuario)) || Number(id_usuario) <= 0) {
      throw new BadRequestException('Usuario no válido');
    }

    return this.mutateAccount(Number(id_usuario), async (manager) => {
      await manager.query(
        `
      UPDATE core.alexa_account_links
      SET active = false,
          last_used_at = CURRENT_TIMESTAMP
      WHERE id_usuario = $1
        AND active = true;
      `,
        [Number(id_usuario)],
      );

      return {
        message: 'Alexa se desvinculó correctamente.',
        isLinked: false,
        linkedAt: null,
      };
    });
  }

  async verifyAlexaVerificationCode(
    token: string,
    alexaUserId: string,
    alexaDeviceId?: string,
  ): Promise<User> {
    const tokenn = String(token || '').replace(/\D/g, '');
    const cleanAlexaUserId = this.sanitizeAlexaIdentifier(alexaUserId, 255);
    const cleanAlexaDeviceId = this.sanitizeAlexaIdentifier(alexaDeviceId, 255);

    if (!/^\d{6}$/.test(tokenn)) {
      throw new BadRequestException('El código debe tener 6 dígitos');
    }

    if (!cleanAlexaUserId) {
      throw new BadRequestException('El usuario de Alexa es obligatorio');
    }

    const linkedRows = await this.readerDataSource.query(
      `
      SELECT id_usuario
      FROM core.alexa_account_links
      WHERE alexa_user_id = $1
        AND active = true
      LIMIT 1;
      `,
      [cleanAlexaUserId],
    );

    if (linkedRows[0]) {
      throw new BadRequestException(
        'Esta cuenta de Alexa ya está vinculada. Cierra sesión para vincular otra cuenta.',
      );
    }

    const tokenHash = this.hashAlexaToken(tokenn);
    // Identify the owner without locking the code first. All mutations use
    // the same account-first lock order as deletion, then revalidate the code.
    const candidates = await this.readerDataSource.query(
      `SELECT id_usuario FROM core.alexa_codes
       WHERE token_hash = $1 AND purpose = 'ALEXA'
       ORDER BY created_at DESC LIMIT 1`,
      [tokenHash],
    );
    const ownerId = Number(candidates[0]?.id_usuario);
    if (!Number.isSafeInteger(ownerId) || ownerId <= 0) {
      throw new BadRequestException('Código inválido o expirado');
    }

    return this.mutateAccount(ownerId, async (manager, user) => {
      const rows = await manager.query(
        `
        SELECT
          ac.id_alexa_code,
          ac.id_usuario,
          ac.expires_at,
          ac.used_at,
          ac.attempts,
          u.email,
          u.activo
        FROM core.alexa_codes ac
        INNER JOIN core.users u
          ON u.id_usuario = ac.id_usuario
        WHERE ac.token_hash = $1
          AND ac.id_usuario = $2
          AND ac.purpose = 'ALEXA'
        ORDER BY ac.created_at DESC
        LIMIT 1
        FOR UPDATE;
        `,
        [tokenHash, ownerId],
      );

      const codeRow = rows[0];

      if (!codeRow) {
        throw new BadRequestException('Código inválido o expirado');
      }

      if (codeRow.activo !== 1) {
        throw new BadRequestException('La cuenta no está activa');
      }

      if (codeRow.used_at) {
        throw new BadRequestException('El código ya fue usado');
      }

      if (!codeRow.expires_at || new Date() > new Date(codeRow.expires_at)) {
        await manager.query(
          `
          UPDATE core.alexa_codes
          SET used_at = CURRENT_TIMESTAMP,
              attempts = 0
          WHERE id_alexa_code = $1;
          `,
          [codeRow.id_alexa_code],
        );
        throw new BadRequestException('El código ha expirado');
      }

      if (Number(codeRow.attempts || 0) <= 0) {
        throw new BadRequestException(
          'Se han agotado los intentos. Solicita un nuevo código.',
        );
      }

      await manager.query(
        `
        UPDATE core.alexa_codes
        SET used_at = CURRENT_TIMESTAMP
        WHERE id_alexa_code = $1;
        `,
        [codeRow.id_alexa_code],
      );

      await manager.query(
        `
        INSERT INTO core.alexa_account_links (
          id_usuario,
          alexa_user_id,
          alexa_device_id,
          linked_at,
          last_used_at,
          active
        )
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, true)
        ON CONFLICT (alexa_user_id)
        DO UPDATE SET
          id_usuario = EXCLUDED.id_usuario,
          alexa_device_id = EXCLUDED.alexa_device_id,
          linked_at = CURRENT_TIMESTAMP,
          last_used_at = CURRENT_TIMESTAMP,
          active = true;
        `,
        [codeRow.id_usuario, cleanAlexaUserId, cleanAlexaDeviceId || null],
      );

      return user;
    });
  }

  private async getActiveAlexaCodeForUser(
    user: User,
    manager?: EntityManager,
  ): Promise<{
    message: string;
    email: string;
    token: string | null;
    expiresAt: string | null;
    remainingSeconds: number;
    hasActiveCode: boolean;
    isLinked: boolean;
    linkedAt: string | null;
  }> {
    const linkStatus = await this.getAlexaLinkStatusForUser(
      user.id_usuario,
      manager,
    );
    const rows = await (manager ?? this.readerDataSource).query(
      `
      SELECT
        id_alexa_code,
        to_char(expires_at, 'YYYY-MM-DD"T"HH24:MI:SS.MS') || 'Z' AS expires_at,
        GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (expires_at - CURRENT_TIMESTAMP))))::int AS remaining_seconds,
        attempts
      FROM core.alexa_codes
      WHERE id_usuario = $1
        AND purpose = 'ALEXA'
        AND used_at IS NULL
        AND expires_at > CURRENT_TIMESTAMP
        AND attempts > 0
      ORDER BY created_at DESC
      LIMIT 1;
      `,
      [user.id_usuario],
    );

    const active = rows[0];

    if (!active) {
      return {
        message: 'No hay código de Alexa activo.',
        email: user.email,
        token: null,
        expiresAt: null,
        remainingSeconds: 0,
        hasActiveCode: false,
        ...linkStatus,
      };
    }

    return {
      message: 'Código de Alexa activo.',
      email: user.email,
      token: null,
      expiresAt: active.expires_at,
      remainingSeconds: Number(active.remaining_seconds || 0),
      hasActiveCode: true,
      ...linkStatus,
    };
  }

  private async getAlexaLinkStatusForUser(
    id_usuario: number,
    manager?: EntityManager,
  ): Promise<{ isLinked: boolean; linkedAt: string | null }> {
    const rows = await (manager ?? this.readerDataSource).query(
      `
      SELECT to_char(linked_at, 'YYYY-MM-DD"T"HH24:MI:SS.MS') || 'Z' AS linked_at
      FROM core.alexa_account_links
      WHERE id_usuario = $1
        AND active = true
      ORDER BY linked_at DESC
      LIMIT 1;
      `,
      [Number(id_usuario)],
    );

    return {
      isLinked: !!rows[0],
      linkedAt: rows[0]?.linked_at || null,
    };
  }

  private getRemainingSeconds(expiration: Date): number {
    return Math.max(0, Math.floor((expiration.getTime() - Date.now()) / 1000));
  }

  private hashAlexaToken(token: string): string {
    const normalized = String(token || '').replace(/\D/g, '');
    return crypto
      .createHash('sha256')
      .update(`ALEXA:${normalized}`)
      .digest('hex');
  }

  private sanitizeAlexaIdentifier(
    value: string | undefined,
    maxLength: number,
  ): string {
    return String(value || '')
      .trim()
      .replace(/[<>"'`;{}[\]\\|]/g, '')
      .slice(0, maxLength);
  }

  async getProfile(id_usuario: number) {
    if (!id_usuario) {
      throw new BadRequestException('ID de usuario no proporcionado');
    }

    await this.accountDeletionAccess.assertAllowed(id_usuario);

    const user = await this.userReaderRepository.findOne({
      where: { id_usuario },
      select: [
        'nombre',
        'aPaterno',
        'aMaterno',
        'email',
        'telefono',
        'rol',
        'ubicacion',
        'fecha_creacion',
      ],
    });

    if (!user) {
      throw new BadRequestException('El usuario no existe.');
    }

    return user;
  }

  async updateUserProfile(id_usuario: number, dto: UpdateUserDto) {
    const user = await this.userReaderRepository.findOne({
      where: { id_usuario },
    });
    if (!user) throw new BadRequestException('El usuario no existe');

    return this.accountDeletionAccess.withAccountLock(
      id_usuario,
      async (manager, user) => {
        const repository = manager.getRepository(User);
        const normalizedEmail = dto.email?.trim().toLowerCase();
        if (normalizedEmail && normalizedEmail !== user.email) {
          const exists = await this.userReaderRepository.findOne({
            where: { email: normalizedEmail },
          });
          if (exists)
            throw new BadRequestException('El correo ingresado ya está en uso');
          user.email = normalizedEmail;
          user.email_verified = 0;
          user.token_verificacion = '';
          user.token_expiracion = null;
          user.intentos_token = 0;
          await this.accountDeletionAccess.invalidateChallenges(
            id_usuario,
            manager,
          );
        }

        if (dto.telefono && dto.telefono !== user.telefono) {
          const exists = await this.userReaderRepository.findOne({
            where: { telefono: dto.telefono },
          });
          if (exists)
            throw new BadRequestException(
              'El teléfono ingresado ya está en uso',
            );
          user.telefono = dto.telefono;
        }

        if (dto.nombre) user.nombre = dto.nombre;
        if (dto.aPaterno) user.aPaterno = dto.aPaterno;
        if (dto.aMaterno) user.aMaterno = dto.aMaterno;

        if (dto.passw) {
          const salt = await bcrypt.genSalt(10);
          user.passw = await bcrypt.hash(dto.passw, salt);
        }

        user.fecha_actualizacion = new Date();
        await repository.save(user);

        const { passw, ...result } = user;
        return {
          message: 'Perfil actualizado correctamente',
          user: result,
        };
      },
    );
  }

  async findUserById(id_usuario: number): Promise<User> {
    await this.accountDeletionAccess.assertAllowed(id_usuario);
    const user = await this.userReaderRepository.findOne({
      where: { id_usuario },
    });
    if (!user) throw new BadRequestException('Usuario no encontrado');
    return user;
  }
}
