/* eslint-disable */
import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, MoreThan, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';

import { User } from '../entities/user.entity';
import { UserSession } from '../entities/user-session.entity';

export interface SessionContext {
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
export class UserSessionService {
  private readonly accessTokenTtl = '15m';
  private readonly refreshTokenTtl = '7d';
  private readonly refreshTokenDurationMs = 7 * 24 * 60 * 60 * 1000;

  constructor(
    @InjectRepository(User, 'readerConnection')
    private readonly userReaderRepository: Repository<User>,
    @InjectRepository(UserSession, 'editorConnection')
    private readonly userSessionEditorRepository: Repository<UserSession>,
    @InjectRepository(UserSession, 'readerConnection')
    private readonly userSessionReaderRepository: Repository<UserSession>,
    private readonly configService: ConfigService,
  ) {}

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

  private async findReusableSession(
    user: User,
    context: SessionContext,
  ): Promise<UserSession | undefined> {
    const activeSessions = await this.userSessionReaderRepository.find({
      where: {
        id_usuario: user.id_usuario,
        revocada_en: IsNull(),
        expira_en: MoreThan(new Date()),
      },
      order: {
        ultima_actividad: 'DESC',
      },
      take: 5,
    });

    if (!activeSessions.length) {
      return undefined;
    }

    const normalizedDeviceName = context.deviceName?.trim();
    const normalizedUserAgent = context.userAgent?.trim();

    return (
      activeSessions.find((session) => {
        if (normalizedDeviceName && session.device_name === normalizedDeviceName) {
          return true;
        }

        if (
          !normalizedDeviceName &&
          normalizedUserAgent &&
          session.user_agent === normalizedUserAgent
        ) {
          return true;
        }

        return false;
      }) ?? activeSessions[0]
    );
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

    const savedSession = await this.persistSession(
      user,
      refreshToken,
      context,
      session,
    );

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

  async issueSessionTokensForUser(user: User, context: SessionContext) {
    const existingSession = await this.findReusableSession(user, context);
    return this.issueSessionTokens(user, context, existingSession);
  }

  async isSessionActive(sessionId: string): Promise<boolean> {
    const session = await this.getActiveSession(sessionId);
    return !!session;
  }

  async logout(sessionId: string): Promise<{ message: string }> {
    await this.revokeSession(sessionId, 'logout');
    return { message: 'Sesión cerrada correctamente.' };
  }

  async loginUser(email: string, passw: string, context: SessionContext) {
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

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!email || !emailRegex.test(email)) {
      throw new BadRequestException({
        message: 'El correo no tiene un formato válido',
        code: 3,
      });
    }

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

    if (user.email_verified === 0) {
      throw new BadRequestException({
        message: 'La cuenta no está activada. Revise su bandeja de entrada.',
        code: 2,
      });
    }

    if (!passw || passw.length < 8) {
      throw new BadRequestException({
        message: 'La contraseña debe tener mínimo 8 caracteres.',
        code: 3,
      });
    }

    const isPasswordValid = await bcrypt.compare(passw, user.passw);

    if (!isPasswordValid) {
      throw new BadRequestException({
        message: 'Revisa que tu información sea correcta. Intenta de nuevo',
        code: 1,
      });
    }

    const existingSession = await this.findReusableSession(user, context);
    return this.issueSessionTokens(user, context, existingSession);
  }

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

  async restoreSessionFromAccessToken(
    accessToken: string,
    context: SessionContext,
  ) {
    try {
      const decoded = jwt.verify(
        accessToken,
        this.configService.getOrThrow<string>('JWT_SECRET'),
      ) as SessionTokenPayload;

      const session = await this.getActiveSession(decoded.sessionId);
      if (!session || session.id_usuario !== decoded.id_usuario) {
        throw new UnauthorizedException('La sesión ya no está activa');
      }

      const user = await this.findUserById(decoded.id_usuario);
      return this.issueSessionTokens(user, context, session);
    } catch (error) {
      throw new UnauthorizedException('No fue posible restaurar la sesión');
    }
  }

  async findUserById(id_usuario: number): Promise<User> {
    const user = await this.userReaderRepository.findOne({
      where: { id_usuario },
    });
    if (!user) throw new BadRequestException('Usuario no encontrado');
    return user;
  }
}
