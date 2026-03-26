/* eslint-disable */
import {
  Injectable,
  BadRequestException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { MailService } from '../../services/mail/mail.service';
import { InjectRepository, InjectDataSource } from '@nestjs/typeorm';
import { OAuth2Client } from 'google-auth-library';
import { ConfigService } from '@nestjs/config';
import { User } from './entities/user.entity';
import { UserSession } from './entities/user-session.entity';
import { Roles } from './entities/roles.entity';
import { Repository, DataSource } from 'typeorm';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

interface SessionContext {
  ipAddress: string | null;
  userAgent: string | null;
  deviceName?: string;
}

interface SessionTokenPayload {
  id_usuario: number;
  email: string;
  nombre: string;
  rol: number;
  sessionId: string;
}

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);
  private googleClient: OAuth2Client;
  private readonly accessTokenTtl = '15m';
  private readonly refreshTokenTtl = '7d';
  private readonly refreshTokenDurationMs = 7 * 24 * 60 * 60 * 1000;
  constructor(
    //  AGREGAR ESTOS DOS DATASOURCES
    @InjectDataSource('editorConnection')
    private readonly editorDataSource: DataSource,

    @InjectDataSource('readerConnection')
    private readonly readerDataSource: DataSource,

    // EDITOR: Para operaciones CRUD normales (CREATE, UPDATE)
    @InjectRepository(User, 'editorConnection')
    private readonly userEditorRepository: Repository<User>,

    // READER: Para consultas de solo lectura (SELECT)
    @InjectRepository(User, 'readerConnection')
    private readonly userReaderRepository: Repository<User>,

    // ADMIN: Para operaciones administrativas (DELETE, actualizar roles)
    @InjectRepository(User, 'adminConnection')
    private readonly userAdminRepository: Repository<User>,

    @InjectRepository(UserSession, 'editorConnection')
    private readonly userSessionEditorRepository: Repository<UserSession>,

    @InjectRepository(UserSession, 'readerConnection')
    private readonly userSessionReaderRepository: Repository<UserSession>,

    // Roles siempre con EDITOR (son datos de catálogo, pocos cambios)
    @InjectRepository(Roles, 'editorConnection')
    private readonly rolesRepository: Repository<Roles>,

    private readonly configService: ConfigService,
    private readonly mailService: MailService,
  ) {
    this.googleClient = new OAuth2Client(
      this.configService.get('GOOGLE_CLIENT_ID'),
    );
  }

  private normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  private buildTokenPayload(
    user: User,
    sessionId: string,
  ): SessionTokenPayload {
    return {
      id_usuario: user.id_usuario,
      email: user.email,
      nombre: user.nombre,
      rol: user.rol,
      sessionId,
    };
  }

  private getRefreshExpirationDate(): Date {
    return new Date(Date.now() + this.refreshTokenDurationMs);
  }

  private async persistSession(
    user: User,
    refreshToken: string,
    context: SessionContext,
    sessionRecord: UserSession,
  ): Promise<UserSession> {
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    const session = {
      ...sessionRecord,
      refresh_token_hash: refreshTokenHash,
      device_name: context.deviceName ?? sessionRecord.device_name ?? null,
      user_agent: context.userAgent ?? sessionRecord.user_agent ?? null,
      ip_address: context.ipAddress ?? sessionRecord.ip_address ?? null,
      expira_en: this.getRefreshExpirationDate(),
      revocada_en: null,
      motivo_revocacion: null,
      ultima_actividad: new Date(),
    };

    return this.userSessionEditorRepository.save(session);
  }

  private createSessionRecord(
    user: User,
    context: SessionContext,
    existingSession?: UserSession,
  ): UserSession {
    return existingSession
      ? {
          ...existingSession,
          device_name: context.deviceName ?? existingSession.device_name ?? null,
          user_agent: context.userAgent ?? existingSession.user_agent ?? null,
          ip_address: context.ipAddress ?? existingSession.ip_address ?? null,
          expira_en: this.getRefreshExpirationDate(),
          ultima_actividad: new Date(),
        }
      : this.userSessionEditorRepository.create({
          id_sesion: crypto.randomUUID(),
          id_usuario: user.id_usuario,
          device_name: context.deviceName ?? null,
          user_agent: context.userAgent ?? null,
          ip_address: context.ipAddress ?? null,
          expira_en: this.getRefreshExpirationDate(),
          ultima_actividad: new Date(),
        });
  }

  private async issueSessionTokens(
    user: User,
    context: SessionContext,
    existingSession?: UserSession,
  ) {
    const session = this.createSessionRecord(user, context, existingSession);

    const payload = this.buildTokenPayload(user, session.id_sesion);
    const accessToken = jwt.sign(
      payload,
      this.configService.getOrThrow<string>('JWT_SECRET'),
      { expiresIn: this.accessTokenTtl },
    );

    const refreshToken = jwt.sign(
      payload,
      this.configService.getOrThrow<string>('JWT_REFRESH_SECRET'),
      { expiresIn: this.refreshTokenTtl },
    );

    const savedSession = await this.persistSession(user, refreshToken, context, session);

    return {
      accessToken,
      refreshToken,
      sessionId: savedSession.id_sesion,
      accessTokenExpiresIn: this.accessTokenTtl,
      refreshTokenExpiresIn: this.refreshTokenTtl,
    };
  }

  private async getActiveSession(sessionId: string): Promise<UserSession | null> {
    const session = await this.userSessionReaderRepository.findOne({
      where: { id_sesion: sessionId },
    });

    if (!session) {
      return null;
    }

    if (session.revocada_en || session.expira_en <= new Date()) {
      return null;
    }

    return session;
  }

  private async revokeSession(
    sessionId: string,
    reason: string,
  ): Promise<void> {
    const session = await this.userSessionEditorRepository.findOne({
      where: { id_sesion: sessionId },
    });

    if (!session || session.revocada_en) {
      return;
    }

    session.revocada_en = new Date();
    session.motivo_revocacion = reason;
    session.ultima_actividad = new Date();
    await this.userSessionEditorRepository.save(session);
  }

  async isSessionActive(sessionId: string): Promise<boolean> {
    const session = await this.getActiveSession(sessionId);
    return !!session;
  }

  async logout(sessionId: string): Promise<{ message: string }> {
    await this.revokeSession(sessionId, 'logout');
    return { message: 'Sesión cerrada correctamente.' };
  }

  //! funcion para registrar el usuario (USA EDITOR - CREATE)
  async createUser(createUserDto: CreateUserDto): Promise<User> {
    //^ validaciones para correo
    if (!createUserDto.email) {
      throw new BadRequestException('El correo es obligatorio');
    }
    const email = createUserDto.email.trim().toLowerCase();

    // Regex para validar formato de correo
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('El correo no tiene un formato válido');
    }

    // Verificar si el usuario ya existe (USA READER - SELECT)
    const existingUser = await this.userReaderRepository.findOne({
      where: { email },
    });
    if (existingUser) {
      throw new BadRequestException(
        'Revisa que tu información sea correcta. Intenta de nuevo',
      );
    }

    //^ validaciones para telefono
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

    //^ validaciones para contraseña
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!#$%&¿?@*_/-])[A-Za-z\d!#$%&¿?@*_/-]{12,}$/;

    if (!passwordRegex.test(createUserDto.passw)) {
      throw new BadRequestException(
        'La contraseña debe tener mínimo 12 caracteres, una mayúscula, una minúscula, un número y un carácter especial (!#$%&¿?@*_-/), y sin recuencias(123)',
      );
    }
    const hashedPassword = await bcrypt.hash(createUserDto.passw, 10);

    const code = crypto.randomInt(100000, 1000000).toString();

    const expirationDate = new Date(Date.now() + 24 * 60 * 60 * 1000); // token 1d

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

    // enviar correo
    try {
      await this.mailService.sendVerificationEmail(
        newUser.email,
        newUser.nombre,
        code,
      );
    } catch (error) {
      await this.userEditorRepository.delete({ email: newUser.email });
      this.logger.error(error);
      throw new BadRequestException(
        'Revisa que tu información sea correcta. Intenta de nuevo 1.' + error,
      );
    }

    return newUser;
  }

  //! funcion para activar cuenta de usuario (USA EDITOR - UPDATE)
  async verifyEmail(
    email: string,
    token: string,
  ): Promise<{ message: string }> {
    try {
      // Validaciones
      if (!email) {
        throw new BadRequestException('El correo es obligatorio');
      }

      if (!token) {
        throw new BadRequestException('El código es obligatorio');
      }

      if (token.length !== 6) {
        throw new BadRequestException('El código debe tener 6 dígitos');
      }

      // Buscar usuario SOLO por email (USA READER - SELECT)
      const user = await this.userReaderRepository.findOne({
        where: { email },
      });

      if (!user) {
        throw new BadRequestException(
          'Revisa que tu información sea correcta. Intenta de nuevo',
        );
      }

      const now = new Date();

      // Validar expiración
      if (!user.token_expiracion || now > user.token_expiracion) {
        user.token_verificacion = '';
        user.token_expiracion = null;
        user.intentos_token = 0;
        await this.userEditorRepository.save(user); // EDITOR para UPDATE

        throw new BadRequestException(
          'El token ha expirado, solicita uno nuevo.',
        );
      }

      // Validar intentos disponibles
      if (typeof user.intentos_token !== 'number' || user.intentos_token <= 0) {
        user.token_verificacion = '';
        user.token_expiracion = null;
        user.intentos_token = 0;
        await this.userEditorRepository.save(user); // EDITOR para UPDATE

        throw new BadRequestException(
          'Se han agotado los intentos. Solicita un nuevo token.',
        );
      }

      // Validar token incorrecto
      if (user.token_verificacion !== token) {
        user.intentos_token -= 1;
        await this.userEditorRepository.save(user); // EDITOR para UPDATE

        if (user.intentos_token <= 0) {
          user.token_verificacion = '';
          user.token_expiracion = null;
          user.intentos_token = 0;
          await this.userEditorRepository.save(user); // EDITOR para UPDATE

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

      // Token válido → activar cuenta
      user.email_verified = 1;
      user.activo = 1;
      // user.token_verificacion = '';
      // user.token_expiracion = null;
      // user.intentos_token = 0;

      await this.userEditorRepository.save(user); // EDITOR para UPDATE

      return { message: 'Cuenta verificada correctamente.' };
    } catch (error) {
      throw error;
    }
  }

  //! funcion para reenviar correo de verificacion (USA EDITOR - UPDATE)
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
      if (existingUser.email_verified === 1) {
        throw new BadRequestException('La cuenta ya está verificada.');
      }

      const code = crypto.randomInt(100000, 1000000).toString();

      const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000);

      existingUser.token_verificacion = code;
      existingUser.token_expiracion = expiration;
      existingUser.intentos_token = 3;

      await this.userEditorRepository.save(existingUser); // EDITOR para UPDATE

      await this.mailService.resendVerificationEmail(
        existingUser.email,
        existingUser.nombre,
        code,
      );

      return {
        message: 'Codigo enviado correctamente. Revise su bandeja de entrada.',
      };
    } catch (error) {
      throw error;
    }
  }

  //! funcion para inicio de sesion de usuario (USA READER - SELECT)
  async loginUser(email: string, passw: string, context: SessionContext) {
    // Validación de correo
    if (!email || !email.trim()) {
      throw new BadRequestException({
        message: 'El correo es obligatorio',
        code: 3,
      });
    }

    if (!passw || !passw.trim()) {
      throw new BadRequestException({
        message: 'La contraseña es obligatoria',
        code: 3,
      });
    }

    // Validacion de correo vacio o formato incorrecto
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!email || !emailRegex.test(email)) {
      throw new BadRequestException({
        message: 'El correo no tiene un formato válido',
        code: 3,
      });
    }

    // Buscar usuario (USA READER - SELECT)
    const normalizedEmail = this.normalizeEmail(email);
    const user = await this.userReaderRepository.findOne({
      where: { email: normalizedEmail },
    });

    if (!user) {
      throw new BadRequestException({
        message: 'Revisa que tu información sea correcta. Intenta de nuevo',
        code: 1,
      });
    }

    // Verificar si esta activado
    if (user.email_verified === 0) {
      throw new BadRequestException({
        message: 'La cuenta no está activada. Revise su bandeja de entrada.',
        code: 2,
      });
    }

    // Validacion de contraseña
    if (!passw || passw.length < 8) {
      throw new BadRequestException({
        message: 'La contraseña debe tener mínimo 8 caracteres.',
        code: 3,
      });
    }

    // Verificar contraseña
    const isPasswordValid = await bcrypt.compare(passw, user.passw);

    if (!isPasswordValid) {
      throw new BadRequestException({
        message: 'Revisa que tu información sea correcta. Intenta de nuevo',
        code: 1,
      });
    }

    return this.issueSessionTokens(user, context);
  }

  //! funcion para validaciones de token (NO USA DB)
  async refreshToken(refreshToken: string, context: SessionContext) {
    try {
      const decoded = jwt.verify(
        refreshToken,
        this.configService.getOrThrow<string>('JWT_REFRESH_SECRET'),
      ) as SessionTokenPayload;

      const session = await this.getActiveSession(decoded.sessionId);
      if (!session || session.id_usuario !== decoded.id_usuario) {
        throw new UnauthorizedException('La sesión ya no está activa');
      }

      const isRefreshTokenValid = await bcrypt.compare(
        refreshToken,
        session.refresh_token_hash,
      );

      if (!isRefreshTokenValid) {
        await this.revokeSession(decoded.sessionId, 'refresh_token_mismatch');
        throw new UnauthorizedException('Refresh token inválido');
      }

      const user = await this.findUserById(decoded.id_usuario);
      return this.issueSessionTokens(user, context, session);
    } catch (error) {
      throw new UnauthorizedException('Refresh token inválido');
    }
  }

  //! funcion para perfil de usuario (USA READER - SELECT)
  async getProfile(id_usuario: number) {
    this.logger.log('Buscando perfil para ID:', id_usuario);

    if (!id_usuario) {
      throw new BadRequestException('ID de usuario no proporcionado');
    }

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
      this.logger.log(`Usuario con ID ${id_usuario} no encontrado`);
      throw new BadRequestException('El usuario no existe.');
    }

    this.logger.log('Usuario encontrado:', user);
    return user;
  }

  //! funcion para actualizar datos de perfil de usuario (USA EDITOR - UPDATE)
  async updateUserProfile(id_usuario: number, dto: UpdateUserDto) {
    // READER para verificar existencia
    const user = await this.userReaderRepository.findOne({
      where: { id_usuario },
    });
    if (!user) throw new BadRequestException('El usuario no existe');

    // Validar email si quiere cambiarlo (READER para verificar duplicados)
    if (dto.email && dto.email !== user.email) {
      const exists = await this.userReaderRepository.findOne({
        where: { email: dto.email },
      });
      if (exists)
        throw new BadRequestException('El correo ingresado ya está en uso');
      user.email = dto.email;
    }

    // Validar teléfono si quiere cambiarlo (READER para verificar duplicados)
    if (dto.telefono && dto.telefono !== user.telefono) {
      const exists = await this.userReaderRepository.findOne({
        where: { telefono: dto.telefono },
      });
      if (exists)
        throw new BadRequestException('El teléfono ingresado ya está en uso');
      user.telefono = dto.telefono;
    }

    // Actualizar datos básicos
    if (dto.nombre) user.nombre = dto.nombre;
    if (dto.aPaterno) user.aPaterno = dto.aPaterno;
    if (dto.aMaterno) user.aMaterno = dto.aMaterno;

    // *** CORREGIDO: Validar contraseña actual antes de cambiarla ***
    if (dto.passw) {
      // Aquí necesitamos la contraseña actual para validar
      // PERO como no viene en el DTO, debemos obtenerla de otra forma
      // Lo ideal es que el frontend envíe la contraseña actual y la nueva
      // Pero como tu DTO solo tiene passw (nueva), necesitamos modificar el DTO

      // Por ahora, asumimos que si viene passw, es porque ya se validó en el controller
      // con un middleware o guard que verificó la contraseña actual
      const salt = await bcrypt.genSalt(10);
      user.passw = await bcrypt.hash(dto.passw, salt);
    }

    user.fecha_actualizacion = new Date();
    await this.userEditorRepository.save(user); // EDITOR para UPDATE

    // No devolver la contraseña
    const { passw, ...result } = user;
    return {
      message: 'Perfil actualizado correctamente',
      user: result,
    };
  }

  //! funcion para buscar usuario por id (USA READER - SELECT)
  async findUserById(id_usuario: number): Promise<User> {
    const user = await this.userReaderRepository.findOne({
      where: { id_usuario },
    });
    if (!user) throw new BadRequestException('Usuario no encontrado');
    return user;
  }

  //! funcion para verificar correo de usuario y enviar token de recuperacion (USA READER y EDITOR)
  async verifyUserEmail(email: string) {
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
      if (existingUser.email_verified != 1) {
        throw new BadRequestException(
          'La cuenta aún no esta activada. Intenta de nuevo',
        );
      }

      const token = crypto.randomInt(100000, 1000000).toString();

      const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000);

      existingUser.token_verificacion = token;
      existingUser.token_expiracion = expiration;
      existingUser.intentos_token = 3;

      await this.userEditorRepository.save(existingUser); // EDITOR para UPDATE

      await this.mailService.sendRecoveryEmail(
        existingUser.email,
        existingUser.nombre,
        token,
      );

      return { message: 'Correo de recuperación enviado correctamente.' };
    } catch (error) {
      throw error;
    }
  }

  //! funcion para verificar el token de recuperacion de contraseña (USA READER y EDITOR)
  async verifyUserToken(
    email: string,
    token: string,
  ): Promise<{ message: string }> {
    try {
      const emaill = email?.trim().toLowerCase();
      const tokenn = token?.trim();

      if (!emaill) throw new BadRequestException('El correo es obligatorio');
      if (!tokenn) throw new BadRequestException('El token es obligatorio');

      if (tokenn.length !== 6) {
        throw new BadRequestException('El token debe tener 6 caracteres');
      }

      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(emaill)) {
        throw new BadRequestException('Formato de correo inválido');
      }

      const existingUser = await this.userReaderRepository.findOne({
        where: { email: emaill },
      });

      if (!existingUser) {
        throw new BadRequestException(
          'Revisa que tu información sea correcta. Intenta de nuevo',
        );
      }

      if (!existingUser.token_verificacion) {
        throw new BadRequestException(
          'No hay un token asociado a este usuario o ya expiro, Solicita un nuevo token.',
        );
      }

      // token expirado
      if (
        !existingUser.token_expiracion ||
        new Date() > existingUser.token_expiracion
      ) {
        // En expiración, si se limpia todo
        existingUser.token_verificacion = '';
        existingUser.token_expiracion = null;
        existingUser.intentos_token = 0;
        await this.userEditorRepository.save(existingUser); // EDITOR para UPDATE

        throw new BadRequestException('El token ha expirado');
      }

      // sin intentos
      if (
        typeof existingUser.intentos_token !== 'number' ||
        existingUser.intentos_token <= 0
      ) {
        existingUser.token_verificacion = '';
        existingUser.token_expiracion = null;
        existingUser.intentos_token = 0;
        await this.userEditorRepository.save(existingUser); // EDITOR para UPDATE
        throw new BadRequestException(
          'Se han agotado los intentos. Solicita un nuevo token.',
        );
      }

      // token incorrecto
      if (existingUser.token_verificacion !== tokenn) {
        existingUser.intentos_token -= 1;

        await this.userEditorRepository.save(existingUser); // EDITOR para UPDATE

        if (existingUser.intentos_token <= 0) {
          existingUser.token_verificacion = '';
          existingUser.token_expiracion = null;
          existingUser.intentos_token = 0;
          await this.userEditorRepository.save(existingUser); // EDITOR para UPDATE
          throw new BadRequestException(
            'Has agotado los intentos. Solicita un nuevo token.',
          );
        }

        throw new BadRequestException('El token es incorrecto');
      }

      existingUser.token_verificacion = '';
      existingUser.token_expiracion = null;
      existingUser.intentos_token = 3;
      await this.userEditorRepository.save(existingUser); // EDITOR para UPDATE

      return { message: 'Token verificado correctamente.' };
    } catch (error) {
      throw error;
    }
  }

  //! funcion para resetear la contraseña de usuario (USA EDITOR - UPDATE)
  async resetPsw(
    email: string,
    psw: string,
    token: string,
  ): Promise<{ message: string }> {
    try {
      const emaill = email?.trim().toLowerCase();
      const newPassword = psw?.trim();
      const thisToken = token?.trim();

      if (!emaill) {
        throw new BadRequestException('El correo es obligatorio');
      }

      if (!thisToken) {
        throw new BadRequestException('El token es obligatorio');
      }

      if (!newPassword) {
        throw new BadRequestException('La contraseña es obligatoria');
      }

      // Validación de correo
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(emaill)) {
        throw new BadRequestException('Formato de correo inválido.');
      }

      // Validación de token
      if (!/^\d{6}$/.test(thisToken)) {
        throw new BadRequestException('El token debe tener 6 dígitos.');
      }

      // Validación de contraseña
      const passwordRegex =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!#$%&¿?@*_/-])[A-Za-z\d!#$%&¿?@*_/-]{12,}$/;

      if (!passwordRegex.test(newPassword)) {
        throw new BadRequestException(
          'La contraseña debe tener mínimo 12 caracteres, una mayúscula, una minúscula, un número y un carácter especial (!#$%&¿?@*_-/), y sin recuencias(123)',
        );
      }

      // Buscar usuario
      const user = await this.userReaderRepository.findOne({
        where: { email: emaill },
      });

      if (!user) {
        throw new BadRequestException(
          'Revisa que tu información sea correcta. Intenta de nuevo',
        );
      }

      // Verificar que exista token asociado
      if (!user.token_verificacion) {
        throw new BadRequestException(
          'No hay un token válido asociado a este usuario. Solicita uno nuevo.',
        );
      }

      // Verificar expiración
      if (!user.token_expiracion || new Date() > user.token_expiracion) {
        user.token_verificacion = '';
        user.token_expiracion = null;
        user.intentos_token = 0;

        await this.userEditorRepository.save(user);

        throw new BadRequestException(
          'El token ha expirado. Solicita uno nuevo.',
        );
      }

      // Verificar intentos
      if (
        typeof user.intentos_token !== 'number' ||
        user.intentos_token <= 0
      ) {
        user.token_verificacion = '';
        user.token_expiracion = null;
        user.intentos_token = 0;

        await this.userEditorRepository.save(user);

        throw new BadRequestException(
          'Se han agotado los intentos. Solicita un nuevo token.',
        );
      }

      // Verificar token incorrecto
      if (user.token_verificacion !== thisToken) {
        user.intentos_token -= 1;
        await this.userEditorRepository.save(user);

        if (user.intentos_token <= 0) {
          user.token_verificacion = '';
          user.token_expiracion = null;
          user.intentos_token = 0;

          await this.userEditorRepository.save(user);

          throw new BadRequestException(
            'Has agotado los intentos. Solicita un nuevo token.',
          );
        }

        throw new BadRequestException(
          `El token es incorrecto. Te quedan ${user.intentos_token} intentos.`,
        );
      }

      // Validar que no sea la misma contraseña
      const isSamePassword = await bcrypt.compare(newPassword, user.passw);
      if (isSamePassword) {
        throw new BadRequestException(
          'La nueva contraseña no puede ser igual a la actual.',
        );
      }

      // Encriptar nueva contraseña
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Actualizar contraseña e invalidar token
      user.passw = hashedPassword;
      user.token_verificacion = '';
      user.token_expiracion = null;
      user.intentos_token = 0;

      await this.userEditorRepository.save(user);

      return { message: 'Contraseña actualizada correctamente.' };
    } catch (error) {
      throw error;
    }
  }
  //! funcion para inicio de sesion con google (USA READER y EDITOR)
  async loginWithGoogle(idToken: string, context: SessionContext) {
    try {
      // 1. Verificar token contra Google
      const googleUser = await this.verifyGoogleToken(idToken);

      //this.logger.log(googleUser);
      if (!googleUser.email_verified) {
        throw new BadRequestException(
          'El correo de Google no está verificado.',
        );
      }

      // 2. Buscar usuario existente por correo (READER para SELECT)
      let user = await this.userReaderRepository.findOne({
        where: { email: googleUser.email },
      });

      if (!user) {
        // 3. Crear cuenta automática si no existe (EDITOR para CREATE)
        const randomPassword = crypto.randomBytes(10).toString('hex');
        const hashedPassword = await bcrypt.hash(randomPassword, 10);

        user = this.userEditorRepository.create({
          nombre: googleUser.name,
          aPaterno: googleUser.aPaterno,
          aMaterno: googleUser.aMaterno,
          fecha_creacion: new Date(),
          email: googleUser.email,
          passw: hashedPassword,
          email_verified: 1,
          activo: 1,
          rol: 1,
          google_id: googleUser.googleId,
        });

        await this.userEditorRepository.save(user); // EDITOR para CREATE
      } else {
        // 4. Vincular Google si el usuario ya existía (EDITOR para UPDATE)
        user.google_id = googleUser.googleId;
        user.email_verified = 1;
        user.activo = 1;
        user.token_verificacion = '';
        user.token_expiracion = null;
        await this.userEditorRepository.save(user); // EDITOR para UPDATE
      }

      return this.issueSessionTokens(user, context);
    } catch (error) {
      throw new BadRequestException('Token de Google inválido');
    }
  }

  //! funcion privada para verificar token de google (NO USA DB)
  private async verifyGoogleToken(idToken: string) {
    const ticket = await this.googleClient.verifyIdToken({
      idToken,
      audience: this.configService.get('GOOGLE_CLIENT_ID'),
    });

    const payload = ticket.getPayload();
    if (!payload) throw new Error('Payload vacío');

    const apellidosArray = (payload.family_name ?? '').trim().split(' ');

    const aPaterno = apellidosArray[0] ?? '';
    const aMaterno =
      apellidosArray.length > 1 ? apellidosArray.slice(1).join(' ') : '';

    return {
      email: payload.email ?? '',
      name: payload.given_name ?? '',
      googleId: payload.sub ?? '',
      aPaterno,
      aMaterno,
      email_verified: payload.email_verified ?? false,
    };
  }

  //! funcion para consultar los usuarios recientes (USA READER - SELECT)
  async getRecentUsersCreated(): Promise<any[]> {
    try {
      const result = await this.userReaderRepository.query(
        `SELECT * FROM core.get_recients_users();`,
      );

      return result;
    } catch (error) {
      this.logger.error('ERROR REAL:', error);
      throw error;
    }
  }

  //! funcion para consultar roles de usuario (USA READER - SELECT)
  async getRoles(): Promise<Roles[]> {
    return await this.rolesRepository.find(); // rolesRepository ya usa editorConnection
  }

  //! funcion para consultar todos los usuarios (USA READER - SELECT)
  async getUsers(): Promise<User[]> {
    return await this.userReaderRepository.find();
  }

  //! funcion para actualizar el estado de un usuario (rol, activo) - USA ADMIN
  async updateUserStatus(updateData: UpdateUserDto) {
    const user = await this.userReaderRepository.findOne({
      where: { id_usuario: updateData.id_usuario },
    });

    if (!user) {
      throw new BadRequestException('Usuario no encontrado');
    }

    user.rol = updateData.rol ?? user.rol;
    user.activo = updateData.activo ?? user.activo;

    // ADMIN para operaciones que requieren permisos especiales
    return await this.userAdminRepository.save(user);
  }

  //! funcion para eliminar usuario (USA ADMIN - DELETE)
  async deleteUser(id_usuario: number): Promise<{ message: string }> {
    const user = await this.userReaderRepository.findOne({
      where: { id_usuario },
    });

    if (!user) {
      throw new BadRequestException('Usuario no encontrado');
    }

    await this.userAdminRepository.delete(id_usuario); // ADMIN para DELETE

    return { message: 'Usuario eliminado correctamente' };
  }
}
