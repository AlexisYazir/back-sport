/* eslint-disable */
import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

import { MailService } from '../../../services/mail/mail.service';
import { User } from '../entities/user.entity';

@Injectable()
export class UserPasswordRecoveryService {
  constructor(
    @InjectRepository(User, 'editorConnection')
    private readonly userEditorRepository: Repository<User>,
    @InjectRepository(User, 'readerConnection')
    private readonly userReaderRepository: Repository<User>,
    private readonly mailService: MailService,
  ) {}

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

      await this.userEditorRepository.save(existingUser);

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

      if (
        !existingUser.token_expiracion ||
        new Date() > existingUser.token_expiracion
      ) {
        existingUser.token_verificacion = '';
        existingUser.token_expiracion = null;
        existingUser.intentos_token = 0;
        await this.userEditorRepository.save(existingUser);

        throw new BadRequestException('El token ha expirado');
      }

      if (
        typeof existingUser.intentos_token !== 'number' ||
        existingUser.intentos_token <= 0
      ) {
        existingUser.token_verificacion = '';
        existingUser.token_expiracion = null;
        existingUser.intentos_token = 0;
        await this.userEditorRepository.save(existingUser);
        throw new BadRequestException(
          'Se han agotado los intentos. Solicita un nuevo token.',
        );
      }

      if (existingUser.token_verificacion !== tokenn) {
        existingUser.intentos_token -= 1;

        await this.userEditorRepository.save(existingUser);

        if (existingUser.intentos_token <= 0) {
          existingUser.token_verificacion = '';
          existingUser.token_expiracion = null;
          existingUser.intentos_token = 0;
          await this.userEditorRepository.save(existingUser);
          throw new BadRequestException(
            'Has agotado los intentos. Solicita un nuevo token.',
          );
        }

        throw new BadRequestException('El token es incorrecto');
      }

      existingUser.token_verificacion = '';
      existingUser.token_expiracion = null;
      existingUser.intentos_token = 3;
      await this.userEditorRepository.save(existingUser);

      return { message: 'Token verificado correctamente.' };
    } catch (error) {
      throw error;
    }
  }

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

      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(emaill)) {
        throw new BadRequestException('Formato de correo inválido.');
      }

      if (!/^\d{6}$/.test(thisToken)) {
        throw new BadRequestException('El token debe tener 6 dígitos.');
      }

      const passwordRegex =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!#$%&¿?@*_/-])[A-Za-z\d!#$%&¿?@*_/-]{12,}$/;

      if (!passwordRegex.test(newPassword)) {
        throw new BadRequestException(
          'La contraseña debe tener mínimo 12 caracteres, una mayúscula, una minúscula, un número y un carácter especial (!#$%&¿?@*_-/), y sin recuencias(123)',
        );
      }

      const user = await this.userReaderRepository.findOne({
        where: { email: emaill },
      });

      if (!user) {
        throw new BadRequestException(
          'Revisa que tu información sea correcta. Intenta de nuevo',
        );
      }

      if (!user.token_verificacion) {
        throw new BadRequestException(
          'No hay un token válido asociado a este usuario. Solicita uno nuevo.',
        );
      }

      if (!user.token_expiracion || new Date() > user.token_expiracion) {
        user.token_verificacion = '';
        user.token_expiracion = null;
        user.intentos_token = 0;

        await this.userEditorRepository.save(user);

        throw new BadRequestException(
          'El token ha expirado. Solicita uno nuevo.',
        );
      }

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

      const isSamePassword = await bcrypt.compare(newPassword, user.passw);
      if (isSamePassword) {
        throw new BadRequestException(
          'La nueva contraseña no puede ser igual a la actual.',
        );
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);

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
}
