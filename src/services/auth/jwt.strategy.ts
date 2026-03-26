/* eslint-disable */
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../modules/users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
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
