/* eslint-disable */
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../modules/users/users.service';

const ACCESS_COOKIE_NAME = 'sc_access_token';

function extractTokenFromCookie(req: any, cookieName: string): string | null {
  const cookieHeader = req?.headers?.cookie;
  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(';');
  for (const cookie of cookies) {
    const [name, ...valueParts] = cookie.trim().split('=');
    if (name === cookieName) {
      return decodeURIComponent(valueParts.join('='));
    }
  }

  return null;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: any) => extractTokenFromCookie(req, ACCESS_COOKIE_NAME),
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow<string>('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    if (!payload.sessionId) {
      throw new UnauthorizedException('Sesión inválida');
    }

    const isSessionActive = await this.usersService.isSessionActive(
      payload.sessionId,
    );

    if (!isSessionActive) {
      throw new UnauthorizedException('La sesión ya no está activa');
    }

    return {
      id_usuario: payload.id_usuario,
      email: payload.email,
      nombre: payload.nombre,
      rol: payload.rol,
      sessionId: payload.sessionId,
    };
  }
}
