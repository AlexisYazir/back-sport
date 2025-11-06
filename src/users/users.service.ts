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
    // Verificar si el usuario ya existe
    const existingUser = await this.userRepository.findOne({
      where: { email: createUserDto.email },
    });
    if (existingUser) {
      throw new BadRequestException('El correo ya está registrado');
    }
    // Verificar si el telefono ya existe
    const existingTelefono = await this.userRepository.findOne({
      where: { email: createUserDto.telefono },
    });
    if (existingTelefono) {
      throw new BadRequestException('El telefono ya está registrado');
    }

    const token = jwt.sign(
      { email: createUserDto.email },
      this.configService.getOrThrow<string>('JWT_SECRET'),
      { expiresIn: '1d' },
    );
    const hashedPassword = await bcrypt.hash(createUserDto.passw, 10);

    const newUser = this.userRepository.create({
      ...createUserDto,
      passw: hashedPassword,
      email_verified: 0,
      token_verificacion: token,
      fecha_creacion: new Date(),
      activo: 1,
      rol: 1,
    });

    await this.userRepository.save(newUser);

    // Enviar correo
    await this.sendVerificationEmail(newUser.email, token);

    return newUser;
  }

  /* funcion para enviar correo de activacion de cuenta */
  private async sendVerificationEmail(
    email: string,
    token: string,
  ): Promise<void> {
    const transporter: Transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: this.configService.getOrThrow<string>('EMAIL_USER'),
        pass: this.configService.getOrThrow<string>('EMAIL_PASS'),
      },
    });

    const url = `https://back-sport.vercel.app/users/verify-email?token=${token}`;

    const mailOptions = {
      from: `"Sport Center" <${this.configService.get<string>('EMAIL_USER')}>`,
      to: email,
      subject: 'Verifica tu cuenta',
      html: `
        <h3>¡Bienvenido a Sport Center!</h3>
        <p>Por favor verifica tu cuenta haciendo clic en el siguiente enlace:</p>
        <a href="${url}" target="_blank">${url}</a>
      `,
    };

    try {
      await transporter.sendMail(mailOptions);
      console.log(`Correo de verificación enviado a: ${email}`);
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
    if (!email) {
      throw new BadRequestException('El correo es obligatorio');
    }
    if (!passw) {
      throw new BadRequestException('La contraseña es obligatoria');
    }

    const user = await this.userRepository.findOne({ where: { email } });
    //console.log(user);
    if (!user) {
      throw new BadRequestException('El correo no esta registrado');
    }

    // Verificar contraseña
    // console.log(`pasw ${passw} y user.passw ${user.passw}`);
    const isPasswordValid = await bcrypt.compare(passw, user.passw);
    if (!isPasswordValid) {
      throw new BadRequestException('Contraseña incorrecta');
    }

    // Verificar que el correo este activado
    if (user.email_verified === 0) {
      throw new BadRequestException('Correo no verificado');
    }
    const token = jwt.sign(
      { id: user.id_usuario, email: user.email, rol: user.rol },
      this.configService.getOrThrow<string>('JWT_SECRET'),
      { expiresIn: '1d' },
    );
    console.log('login exitoso');
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
      if (exists) throw new BadRequestException('El correo ingresado ya está en uso');
      user.email = dto.email;
    }

    if (dto.telefono && dto.telefono !== user.telefono) {
      const exists = await this.userRepository.findOne({
        where: { telefono: dto.telefono },
      });
      if (exists) throw new BadRequestException('El teléfono ingresado ya está en uso');
      user.telefono = dto.telefono;
    }

    if (dto.nombre) user.nombre = dto.nombre;
    if (dto.aPaterno) user.aPaterno = dto.aPaterno;
    if (dto.aMaterno) user.aMaterno = dto.aMaterno;

    user.fecha_actualizacion = new Date();
    await this.userRepository.save(user);

    return { message: 'Perfil actualizado correctamente' };
  }
}
