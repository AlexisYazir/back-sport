/* eslint-disable */
import { Injectable, BadRequestException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { MailService } from '../../services/mail/mail.service';
import { InjectRepository } from '@nestjs/typeorm';
import { OAuth2Client } from 'google-auth-library';
import { ConfigService } from '@nestjs/config';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import * as jwt from 'jsonwebtoken';
import * as dns from 'dns/promises';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

@Injectable()
export class UsersService {
  private googleClient: OAuth2Client;
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    
  ) {
      this.googleClient = new OAuth2Client(
      this.configService.get('GOOGLE_CLIENT_ID'),
    );
  }

  //! funcion para registrar el usuario
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

    // Extraer dominio
    const domain = email.split('@')[1];

    // Lista de dominios institucionales
    const institutionalDomains = [
      'edu.mx',
      'unam.mx',
      'ipn.mx',
      'tecnm.mx',
      'ut.edu.mx',
      'uthh.edu.mx',
      'uabc.mx',
      'uaq.mx',
    ];

    const isInstitutional = institutionalDomains.some((d) =>
      domain.endsWith(d),
    );

    let isRealEmail = false;

    if (isInstitutional) {
      //^ Validación DNS MX para correos institucionales
      try {
        const mxRecords = await dns.resolveMx(domain);
        if (mxRecords.length > 0) {
          isRealEmail = true;
        }
      } catch {
        throw new BadRequestException(
          'El dominio institucional no tiene registros MX válidos.',
        );
      }
    } else {
      //^ Validación con Zeruh para correos no institucionales
      isRealEmail = await this.mailService.validateEmailWithZeruh(email);

      if (!isRealEmail) {
        throw new BadRequestException(
          'El correo no es válido o no puede recibir mensajes. Por favor ingresa un correo real.',
        );
      }
    }

    // Verificar si el usuario ya existe
    const existingUser = await this.userRepository.findOne({
      where: { email },
    });
    if (existingUser) {
      throw new BadRequestException('Revisa que tu información sea correcta. Intenta de nuevo');
    }

    //^ validaciones para telefono
    if (!createUserDto.telefono) {
      throw new BadRequestException('El telefono es obligatorio');
    }

    const existingTelefono = await this.userRepository.findOne({
      where: { telefono: createUserDto.telefono },
    });
    if (existingTelefono) {
      throw new BadRequestException('Revisa que tu información sea correcta. Intenta de nuevo');
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

    const newUser = this.userRepository.create({
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

    await this.userRepository.save(newUser);

    // enviar correo
    try {
      if (isInstitutional) {
        //  para institucionales
        await this.mailService.sendVerificationEmail(
          newUser.email,
          newUser.nombre,
          code,
        );
        //console.log('Correo institucional detectado, enviando verificación…');
      } else {
        // Normal
        await this.mailService.sendVerificationEmail(
          newUser.email,
          newUser.nombre,
          code,
        );
      }
    } catch (error) {
      await this.userRepository.delete({ email: newUser.email });
      console.log(error);
      throw new BadRequestException(
        'Revisa que tu información sea correcta. Intenta de nuevo.',
      );
    }

    return newUser;
  }

  //! funcion para activar cuenta de usuario
  // funcion para activar cuenta de usuario
  async verifyEmail(email: string,token: string,): Promise<{ message: string }> {
    try {
      // Validaciones
      if (!email) { throw new BadRequestException('El correo es obligatorio'); }

      if (!token) { throw new BadRequestException('El código es obligatorio'); }

      if (token.length !== 6) { throw new BadRequestException('El código debe tener 6 dígitos'); }

      // Buscar usuario SOLO por email
      const user = await this.userRepository.findOne({ where: { email },});

      if (!user) { throw new BadRequestException('Revisa que tu información sea correcta. Intenta de nuevo'); }

      const now = new Date();

      // Validar expiración
      if (!user.token_expiracion || now > user.token_expiracion) {
        user.token_verificacion = '';
        user.token_expiracion = null;
        user.intentos_token = 0;
        await this.userRepository.save(user);

        throw new BadRequestException('El token ha expirado, solicita uno nuevo.');
      }

      // Validar intentos disponibles
      if (
        typeof user.intentos_token !== 'number' ||
        user.intentos_token <= 0
      ) {
        user.token_verificacion = '';
        user.token_expiracion = null;
        user.intentos_token = 0;
        await this.userRepository.save(user);

        throw new BadRequestException(
          'Se han agotado los intentos. Solicita un nuevo token.',
        );
      }

      // Validar token incorrecto
      if (user.token_verificacion !== token) {
        user.intentos_token -= 1;
        await this.userRepository.save(user);

        if (user.intentos_token <= 0) {
          user.token_verificacion = '';
          user.token_expiracion = null;
          user.intentos_token = 0;
          await this.userRepository.save(user);

          throw new BadRequestException(
            'Has agotado los intentos. Solicita un nuevo token.',
          );
        }

        throw new BadRequestException('El token es incorrecto'+'. Te quedan '+user.intentos_token+' intentos.' );
      }

      // Token válido → activar cuenta
      user.email_verified = 1;
      user.activo = 1;
      user.token_verificacion = '';
      user.token_expiracion = null;
      user.intentos_token = 0;

      await this.userRepository.save(user);

      return { message: 'Cuenta verificada correctamente.' };
    } catch (error) {
      throw error;
    }
  }

  //! funcion para reenviar correo de verificacion
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

      const existingUser = await this.userRepository.findOne({
        where: { email: emaill },
      });

      if (!existingUser) {
        throw new BadRequestException('Revisa que tu información sea correcta. Intenta de nuevo');
      }
      if (existingUser.email_verified === 1) {
        throw new BadRequestException('La cuenta ya está verificada.');
      }

      const code = crypto.randomInt(100000, 1000000).toString();

      const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000);

      existingUser.token_verificacion = code;
      existingUser.token_expiracion = expiration;
      existingUser.intentos_token = 3;

      await this.userRepository.save(existingUser);

      await this.mailService.resendVerificationEmail(
        existingUser.email,
        existingUser.nombre,
        code,
      );

      return { message: 'Codigo enviado correctamente. Revise su bandeja de entrada.' };
    } catch (error) {
      throw error;
    }
  }

  //! funcion para inicio de sesion de usuario
  async loginUser(email: string, passw: string) {
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

    // Buscar usuario
    const user = await this.userRepository.findOne({ where: { email } });

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

    // Generar token
    const token = jwt.sign(
      { id: user.id_usuario, email: user.email, rol: user.rol },
      this.configService.getOrThrow<string>('JWT_SECRET'),
      { expiresIn: '1d' },
    );

    return { token };
  }

  //! funcion para actualizar datos de perfil de usuario
  async updateUserProfile(id_usuario: number, dto: UpdateUserDto) {
    const user = await this.userRepository.findOne({ where: { id_usuario } });
    if (!user) throw new BadRequestException('El usuario no existe');

    // Validar email si quiere cambiarlo
    if (dto.email && dto.email !== user.email) {
      const exists = await this.userRepository.findOne({
        where: { email: dto.email },
      });
      if (exists)
        throw new BadRequestException('El correo ingresado ya está en uso');
      user.email = dto.email;
    }

    if (dto.telefono && dto.telefono !== user.telefono) {
      const exists = await this.userRepository.findOne({
        where: { telefono: dto.telefono },
      });
      if (exists)
        throw new BadRequestException('El teléfono ingresado ya está en uso');
      user.telefono = dto.telefono;
    }

    if (dto.nombre) user.nombre = dto.nombre;
    if (dto.aPaterno) user.aPaterno = dto.aPaterno;
    if (dto.aMaterno) user.aMaterno = dto.aMaterno;

    user.fecha_actualizacion = new Date();
    await this.userRepository.save(user);

    return { message: 'Perfil actualizado correctamente' };
  }

  //! funcion para verificar correo de usuario y enviar token de recuperacion
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

      const existingUser = await this.userRepository.findOne({
        where: { email: emaill },
      });

      if (!existingUser) {
        throw new BadRequestException('Revisa que tu información sea correcta. Intenta de nuevo');
      }
      if (existingUser.email_verified != 1) {
        throw new BadRequestException('La cuenta aún no esta activada. Intenta de nuevo');
      }

      const token = crypto.randomInt(100000, 1000000).toString();

      const expiration = new Date(Date.now() + 24 * 60 * 60 * 1000);

      existingUser.token_verificacion = token;
      existingUser.token_expiracion = expiration;
      existingUser.intentos_token = 3;

      await this.userRepository.save(existingUser);

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

  //! funcion para verificar el token de recuperacion de contraseña
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

      const existingUser = await this.userRepository.findOne({
        where: { email: emaill },
      });

      if (!existingUser) {
        throw new BadRequestException('Revisa que tu información sea correcta. Intenta de nuevo');
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
        await this.userRepository.save(existingUser);

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
        await this.userRepository.save(existingUser);
        throw new BadRequestException(
          'Se han agotado los intentos. Solicita un nuevo token.',
        );
      }

      // token incorrecto
      if (existingUser.token_verificacion !== tokenn) {
        existingUser.intentos_token -= 1;

        await this.userRepository.save(existingUser);

        if (existingUser.intentos_token <= 0) {
          existingUser.token_verificacion = '';
          existingUser.token_expiracion = null;
          existingUser.intentos_token = 0;
          await this.userRepository.save(existingUser);
          throw new BadRequestException(
            'Has agotado los intentos. Solicita un nuevo token.',
          );
        }

        throw new BadRequestException('El token es incorrecto');
      }

      existingUser.token_verificacion = '';
      existingUser.token_expiracion = null;
      existingUser.intentos_token = 3;
      await this.userRepository.save(existingUser);

      return { message: 'Token verificado correctamente.' };
    } catch (error) {
      throw error;
    }
  }

  //! funcion para resetear la contraseña de usuario
  async resetPsw(email: string, psw: string): Promise<{ message: string }> {
    try {
      const emaill = email?.trim().toLowerCase();
      const newPassword = psw?.trim();

      if (!emaill) throw new BadRequestException('El correo es obligatorio');
      if (!newPassword) throw new BadRequestException('La contraseña es obligatoria');

      // Validación de correo
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(emaill)) {
        throw new BadRequestException('Formato de correo inválido.');
      }

      //^ validaciones para contraseña
      const passwordRegex =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!#$%&¿?@*_/-])[A-Za-z\d!#$%&¿?@*_/-]{12,}$/;

      if (!passwordRegex.test(newPassword)) {
        throw new BadRequestException(
          'La contraseña debe tener mínimo 12 caracteres, una mayúscula, una minúscula, un número y un carácter especial (!#$%&¿?@*_-/), y sin recuencias(123)',
        );
      }

      // Buscar usuario
      const user = await this.userRepository.findOne({
        where: { email: emaill },
      });

      if (!user) {
        throw new BadRequestException('Revisa que tu información sea correcta. Intenta de nuevo');
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

      user.passw = hashedPassword;
      await this.userRepository.save(user);

      return { message: 'Contraseña actualizada correctamente.' };
    } catch (error) {
      //console.log('Reset psw error:', error);
      throw error;
    }
  }

  //! funcion para inicio de sesion con google
  async loginWithGoogle(idToken: string) {
    try {
      // 1. Verificar token contra Google
      const googleUser = await this.verifyGoogleToken(idToken);

      if (!googleUser.email_verified) {
        throw new BadRequestException('El correo de Google no está verificado.');
      }

      // 2. Buscar usuario existente por correo
      let user = await this.userRepository.findOne({
        where: { email: googleUser.email },
      });

      if (!user) {
        // 3. Crear cuenta automática si no existe
        const randomPassword = crypto.randomBytes(10).toString('hex');
        const hashedPassword = await bcrypt.hash(randomPassword, 10);

      user = this.userRepository.create({
        nombre: googleUser.name,
        aPaterno: googleUser.aPaterno,
        aMaterno: googleUser.aPaterno,
        fecha_creacion: new Date(),
        email: googleUser.email,
        passw: hashedPassword,
        email_verified: 1,
        activo: 1,
        rol: 1,
        google_id: googleUser.googleId,
      });

        await this.userRepository.save(user);
      } else {
        // 4. Vincular Google si el usuario ya existía
        user.google_id = googleUser.googleId;
        user.email_verified = 1;
        user.activo = 1;
        user.token_verificacion = '';
        user.token_expiracion = null;
        await this.userRepository.save(user);
      }

      // 5. Crear JWT
      const token = jwt.sign(
        {
          id: user.id_usuario,
          email: user.email,
          rol: user.rol,
        },
        this.configService.getOrThrow<string>('JWT_SECRET'),
        { expiresIn: '1d' },
      );

      return { token, };
    } catch (error) {
      throw new BadRequestException('Token de Google inválido');
    }
  }

  //! funcion privada para verificar token de google
  private async verifyGoogleToken(idToken: string) {
    try {
      const ticket = await this.googleClient.verifyIdToken({
        idToken,
        audience: this.configService.get('GOOGLE_CLIENT_ID'),
      });

      const payload = ticket.getPayload();
      if (!payload) throw new Error('Payload vacío');
      console.log(payload);

      return {
        email: payload.email ?? '',
        name: payload.given_name ?? '',
        googleId: payload.sub ?? '',
        aPaterno: payload.family_name ?? '',
        email_verified: payload.email_verified ?? false,
      };

    } catch (err) {
      throw new BadRequestException('Token de Google inválido');
    }
  }

}
