/* eslint-disable */
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../modules/users/users.service';
import { AccountDeletionAccessService } from '../../modules/account-deletion/account-deletion-access.service';

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
    private readonly accountDeletionAccess: AccountDeletionAccessService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        // An explicit header selects header authentication. Never fall back
        // to a different cookie identity when that header is malformed.
        (req: any) =>
          req?.headers?.authorization !== undefined
            ? null
            : extractTokenFromCookie(req, ACCESS_COOKIE_NAME),
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow<string>('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    if (
      !payload.sessionId ||
      !Number.isSafeInteger(payload.id_usuario) ||
      payload.id_usuario <= 0
    ) {
      throw new UnauthorizedException('Sesión inválida');
    }

    await this.accountDeletionAccess.assertAllowed(payload.id_usuario);

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
