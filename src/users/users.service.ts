import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

import * as bcrypt from 'bcrypt';
import * as nodemailer from 'nodemailer';
import { Transporter } from 'nodemailer';
import axios from 'axios';
import * as dns from 'dns/promises';

import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,

    private readonly configService: ConfigService,
  ) {}

  /* funcion para crear el usuario */
  async createUser(createUserDto: CreateUserDto): Promise<User> {
    // VALIDACIONES PARA EL CORREO
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
      // VALIDACIÓN MX CON Node DNS
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
      // VALIDACIÓN REAL CON ZERUH SOLO PARA CORREOS NO INSTITUCIONALES
      isRealEmail = await this.validateEmailWithZeruh(email);

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

    // VALIDACIONES TELEFONO
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

    // VALIDACIÓN DE CONTRASEÑA
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

    const newUser = this.userRepository.create({
      ...createUserDto,
      email,
      passw: hashedPassword,
      email_verified: 0,
      intentos_token: 0,
      token_verificacion: token,
      fecha_creacion: new Date(),
      activo: 1,
      rol: 1,
    });

    await this.userRepository.save(newUser);

    // Enviar correo
    try {
      if (isInstitutional) {
        // Mensaje especial para institucionales
        await this.sendVerificationEmail(newUser.email, newUser.nombre, token);
        console.log('Correo institucional detectado, enviando verificación…');
      } else {
        // Normal
        await this.sendVerificationEmail(newUser.email, newUser.nombre, token);
      }
    } catch (error) {
      await this.userRepository.delete({ email: newUser.email });
      throw new BadRequestException(
        'No se pudo enviar el correo. Verifica que tu correo exista.',
      );
    }

    return newUser;
  }

  /* funcion para enviar correo de activacion de cuenta */
  private async sendVerificationEmail(
    email: string,
    nombre: string,
    token: string,
  ): Promise<void> {
    const transporter: Transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: this.configService.getOrThrow<string>('EMAIL_USER'),
        pass: this.configService.getOrThrow<string>('EMAIL_PASS'),
      },
    });

    const url = `https://back-sport.vercel.app/users/verify-email/${token}`;

    const mailOptions = {
      from: `"Sport Center" <${this.configService.get<string>('EMAIL_USER')}>`,
      to: email,
      subject: 'Verifica tu cuenta',
      html: `
    <h2>¡Bienvenido a Sport Center, ${nombre}!</h2>
    <p>Gracias por registrarte con nosotros. 
    Para activar tu cuenta y comenzar a disfrutar de nuestros servicios, 
    por favor verifica tu correo electrónico haciendo clic en el siguiente botón:</p>

    <p style="text-align: center; margin: 30px 0;">
    <a href="${url}" target="_blank"
      style="
        background-color: #1a73e8;
           color: white;
           padding: 12px 25px;
           text-decoration: none;
           border-radius: 6px;
           font-size: 16px;
           font-weight: bold;
      "
    >
      Verificar cuenta
    </a>
    </p>
    <p>Si no fuiste tú quien creó esta cuenta, puedes ignorar este mensaje sin problema.</p>

<p>Saludos cordiales,<br>
<b>Sport Center</b></p>
  `,
    };

    try {
      await transporter.sendMail(mailOptions);
      console.log(`Correo enviado: ${email}`);
    } catch (error) {
      if (error instanceof Error) {
        console.error('Error al enviar correo:', error.message);
      } else {
        console.error('Error desconocido al enviar correo');
      }
    }
  }

  /* funcion para activar cuenta de usuario */
  async verifyEmail(token: string): Promise<{ message: string }> {
    try {
      const decoded = jwt.verify(
        token,
        this.configService.getOrThrow<string>('JWT_SECRET'),
      ) as { email: string };

      const user = await this.userRepository.findOne({
        where: { email: decoded.email },
      });

      if (!user) throw new BadRequestException('Usuario no encontrado');

      user.email_verified = 1;
      user.token_verificacion = '';
      await this.userRepository.save(user);

      return { message: 'Correo verificado correctamente.' };
    } catch {
      throw new BadRequestException('Token inválido o expirado');
    }
  }

  /* funcion para inicio de sesion de usuario */
  async loginUser(loginUserDto: LoginUserDto): Promise<{ token: string }> {
    const { email, passw } = loginUserDto;
    //VALIDACIONES PARA EL CORREO
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('El correo no tiene un formato válido');
    }
    if (!email) {
      throw new BadRequestException('El correo es obligatorio');
    }
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new BadRequestException('El correo no esta registrado');
    }
    // Verificar que el correo este activado
    if (user.email_verified === 0) {
      throw new BadRequestException(
        'Correo no verificado. Revise su bandeja de entrada.',
      );
    }
    //VALIDACIONES PARA LA CONTRASEÑA
    if (!passw) {
      throw new BadRequestException('La contraseña es obligatoria');
    }

    if (passw.length < 8) {
      throw new BadRequestException(
        'La contraseña debe tener mínimo 8 caracteres.',
      );
    }
    // Verificar contraseña
    const isPasswordValid = await bcrypt.compare(passw, user.passw);
    if (!isPasswordValid) {
      throw new BadRequestException('Contraseña incorrecta');
    }

    const token = jwt.sign(
      { id: user.id_usuario, email: user.email, rol: user.rol },
      this.configService.getOrThrow<string>('JWT_SECRET'),
      { expiresIn: '1d' },
    );
    //console.log('login exitoso');
    return { token };
  }

  /* funcion para actualizar datos de perfil de usuario */
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

  private async validateEmailWithZeruh(email: string): Promise<boolean> {
    const apiKey = this.configService.get<string>('ZERUH_API_KEY');

    try {
      const response = await axios.get(`https://api.zeruh.com/v1/verify`, {
        params: {
          api_key: apiKey,
          email_address: email,
        },
      });

      const zeruhStatus = response.data?.result?.status;

      // Solo "deliverable" significa correo real existente y con buzón activo.
      return zeruhStatus === 'deliverable';
    } catch (error) {
      console.error(
        'Error al validar correo con Zeruh:',
        error?.message || error,
      );
      return false;
    }
  }
}
