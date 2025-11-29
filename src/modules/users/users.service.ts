/* eslint-disable */
import { Injectable, BadRequestException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { MailService } from '../../mail/mail.service';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import * as jwt from 'jsonwebtoken';
import * as dns from 'dns/promises';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
  ) {}

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
      throw new BadRequestException('El correo ya está registrado');
    }

    //^ validaciones para telefono
    if (!createUserDto.telefono) {
      throw new BadRequestException('El telefono es obligatorio');
    }

    const existingTelefono = await this.userRepository.findOne({
      where: { telefono: createUserDto.telefono },
    });
    if (existingTelefono) {
      throw new BadRequestException('El telefono ya está registrado');
    }

    if (!/^\d{10}$/.test(createUserDto.telefono)) {
      throw new BadRequestException(
        'El telefono debe tener exactamente 10 dígitos numéricos.',
      );
    }

    //^ validaciones para contraseña
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!#$%&¿?@])[A-Za-z\d!#$%&¿?@]{8,}$/;

    if (!passwordRegex.test(createUserDto.passw)) {
      throw new BadRequestException(
        'La contraseña debe tener mínimo 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial (!#$%&¿?@).',
      );
    }
    const hashedPassword = await bcrypt.hash(createUserDto.passw, 10);

    const token = jwt.sign(
      { email: email },
      this.configService.getOrThrow<string>('JWT_SECRET'),
      { expiresIn: '1d' },
    );

    const expirationDate = new Date(Date.now() + 24 * 60 * 60 * 1000); // token 1d

    const newUser = this.userRepository.create({
      ...createUserDto,
      email,
      passw: hashedPassword,
      email_verified: 0,
      intentos_token: 3,
      token_verificacion: token,
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
          token,
        );
        console.log('Correo institucional detectado, enviando verificación…');
      } else {
        // Normal
        await this.mailService.sendVerificationEmail(
          newUser.email,
          newUser.nombre,
          token,
        );
      }
    } catch (error) {
      await this.userRepository.delete({ email: newUser.email });
      console.log(error);
      throw new BadRequestException(
        'No se pudo enviar el correo. Verifica que tu correo exista.',
      );
    }

    return newUser;
  }

  //! funcion para activar cuenta de usuario
  async verifyEmail(token: string): Promise<{ message: string }> {
    try {
      //^  Validar token JWT
      const decoded = jwt.verify(
        token,
        this.configService.getOrThrow<string>('JWT_SECRET'),
      ) as { email: string };

      // Buscar usuario por email Y token
      const user = await this.userRepository.findOne({
        where: {
          email: decoded.email,
          token_verificacion: token,
        },
      });

      if (!user) {
        throw new BadRequestException(
          'Token inválido o no pertenece al usuario',
        );
      }

      // Validar expiración del token
      const now = new Date();
      if (!user.token_expiracion || user.token_expiracion < now) {
        throw new BadRequestException('El token ha expirado, solicita otro');
      }

      user.email_verified = 1;
      user.activo = 1;
      user.token_verificacion = '';
      user.token_expiracion = null;
      await this.userRepository.save(user);

      return { message: 'Correo verificado correctamente.' };
    } catch (error) {
      console.log(error);
      throw new BadRequestException('Token inválido o expirado');
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
        message: 'El correo no está registrado',
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
        message: 'Contraseña incorrecta',
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
        throw new BadRequestException('El correo no está registrado');
      }

      const token = crypto.randomBytes(8).toString('hex');

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

      if (tokenn.length !== 16) {
        throw new BadRequestException('El token debe tener 16 caracteres');
      }

      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(emaill)) {
        throw new BadRequestException('Formato de correo inválido');
      }

      const existingUser = await this.userRepository.findOne({
        where: { email: emaill },
      });

      if (!existingUser) {
        throw new BadRequestException('El correo no está registrado');
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
      if (!newPassword)
        throw new BadRequestException('La contraseña es obligatoria');

      // Validación de correo
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(emaill)) {
        throw new BadRequestException('Formato de correo inválido.');
      }

      // Buscar usuario
      const user = await this.userRepository.findOne({
        where: { email: emaill },
      });

      if (!user) {
        throw new BadRequestException('El correo no está registrado');
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
}
