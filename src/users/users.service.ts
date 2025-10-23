import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginUserDto } from './dto/login-user.dto';

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

  async create(createUserDto: CreateUserDto): Promise<User> {
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
    });

    await this.userRepository.save(newUser);

    // Enviar correo
    await this.sendVerificationEmail(newUser.email, token);

    return newUser;
  }

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

    const url = `http://localhost:3000/users/verify-email?token=${token}`;

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
      await this.userRepository.save(user);

      return { message: '✅ Correo verificado correctamente.' };
    } catch {
      throw new BadRequestException('Token inválido o expirado');
    }
  }
  async loginUser(loginUserDto: LoginUserDto): Promise<{ token: string }> {
    const { email, passw } = loginUserDto;

    // 1. Buscar al usuario por email
    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (!user) {
      throw new BadRequestException('El correo no esta registrado');
    }

    // 2. Verificar contraseña
    const isPasswordValid = await bcrypt.compare(passw, user.passw);
    if (!isPasswordValid) {
      throw new BadRequestException('Contraseña incorrecta');
    }

    // 3. Verificar que el correo esté activado
    if (user.email_verified === 0) {
      throw new BadRequestException('Correo no verificado');
    }

    // 4. Generar JWT
    const token = jwt.sign(
      { id: user.id_usuario, email: user.email, rol: user.rol },
      this.configService.getOrThrow<string>('JWT_SECRET'),
      { expiresIn: '1d' },
    );

    return { token };
  }

  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }

  async findOne(id: number): Promise<User | null> {
    return this.userRepository.findOneBy({ id_usuario: id });
  }

  async update(id: number, updateUserDto: UpdateUserDto): Promise<User | null> {
    await this.userRepository.update(id, updateUserDto);
    return this.findOne(id);
  }

  async remove(id: number): Promise<void> {
    await this.userRepository.delete(id);
  }
}
