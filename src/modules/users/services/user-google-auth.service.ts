/* eslint-disable */
import { Injectable, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { OAuth2Client } from 'google-auth-library';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

import { User } from '../entities/user.entity';
import {
  SessionContext,
  UserSessionService,
} from './user-session.service';

@Injectable()
export class UserGoogleAuthService {
  private googleClient: OAuth2Client;

  constructor(
    @InjectRepository(User, 'editorConnection')
    private readonly userEditorRepository: Repository<User>,
    @InjectRepository(User, 'readerConnection')
    private readonly userReaderRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly userSessionService: UserSessionService,
  ) {
    this.googleClient = new OAuth2Client(
      this.configService.get('GOOGLE_CLIENT_ID'),
    );
  }

  async loginWithGoogle(idToken: string, context: SessionContext) {
    try {
      const googleUser = await this.verifyGoogleToken(idToken);

      if (!googleUser.email_verified) {
        throw new BadRequestException(
          'El correo de Google no está verificado.',
        );
      }

      let user = await this.userReaderRepository.findOne({
        where: { email: googleUser.email },
      });

      if (!user) {
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

        await this.userEditorRepository.save(user);
      } else {
        user.google_id = googleUser.googleId;
        user.email_verified = 1;
        user.activo = 1;
        user.token_verificacion = '';
        user.token_expiracion = null;
        await this.userEditorRepository.save(user);
      }

      return this.userSessionService.issueSessionTokensForUser(user, context);
    } catch (error) {
      throw new BadRequestException('Token de Google inválido');
    }
  }

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
}
