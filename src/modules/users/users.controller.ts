/* eslint-disable */
import { CreateUserDto } from './dto/create-user.dto';
import { GoogleLoginDto } from './dto/google-login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersService } from './users.service';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../../services/auth/roles.guard';
import { Roles } from '../../services/auth/roles.decorator';
import { Throttle } from '@nestjs/throttler';
import * as bcrypt from 'bcrypt';
import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  UseGuards,
  Patch,
  BadRequestException,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';

const ACCESS_COOKIE_NAME = 'sc_access_token';
const REFRESH_COOKIE_NAME = 'sc_refresh_token';

interface SessionContext {
  ipAddress: string | null;
  userAgent: string | null;
  deviceName?: string;
}

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  private isSecureCookie(): boolean {
    return process.env.NODE_ENV === 'production';
  }

  private getCookieOptions(maxAge: number) {
    return {
      httpOnly: true,
      secure: this.isSecureCookie(),
      sameSite: this.isSecureCookie() ? ('none' as const) : ('lax' as const),
      path: '/',
      maxAge,
    };
  }

  private setAuthCookies(
    res: Response,
    tokens: { accessToken: string; refreshToken: string },
  ): void {
    res.cookie(
      ACCESS_COOKIE_NAME,
      tokens.accessToken,
      this.getCookieOptions(15 * 60 * 1000),
    );
    res.cookie(
      REFRESH_COOKIE_NAME,
      tokens.refreshToken,
      this.getCookieOptions(7 * 24 * 60 * 60 * 1000),
    );
  }

  private clearAuthCookies(res: Response): void {
    const baseOptions = {
      httpOnly: true,
      secure: this.isSecureCookie(),
      sameSite: this.isSecureCookie() ? ('none' as const) : ('lax' as const),
      path: '/',
    };

    res.clearCookie(ACCESS_COOKIE_NAME, baseOptions);
    res.clearCookie(REFRESH_COOKIE_NAME, baseOptions);
  }

  private getRefreshTokenFromRequest(req: any, bodyRefreshToken?: string): string | undefined {
    if (bodyRefreshToken?.trim()) {
      return bodyRefreshToken.trim();
    }

    const cookieHeader = req?.headers?.cookie;
    if (!cookieHeader) {
      return undefined;
    }

    const cookies = cookieHeader.split(';');
    for (const cookie of cookies) {
      const [name, ...valueParts] = cookie.trim().split('=');
      if (name === REFRESH_COOKIE_NAME) {
        return decodeURIComponent(valueParts.join('='));
      }
    }

    return undefined;
  }

  private getSessionContext(req: any, deviceName?: string): SessionContext {
    return {
      ipAddress: req.ip ?? req.headers['x-forwarded-for'] ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      deviceName,
    };
  }

  @Post('create-user')
  async createUser(@Body() createUserDto: CreateUserDto) {
    console.log(createUserDto);
    return this.usersService.createUser(createUserDto);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('login-user')
  async loginUser(
    @Body('email') email: string,
    @Body('passw') passw: string,
    @Body('deviceName') deviceName: string | undefined,
    @Req() req: any,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.usersService.loginUser(
      email,
      passw,
      this.getSessionContext(req, deviceName),
    );

    this.setAuthCookies(res, tokens);
    return tokens;
  }
  
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('verify-email')
  async verifyEmail(@Body('email') email: string, @Body('token') token: string) {
    return this.usersService.verifyEmail(email, token);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('resend-code')
  async resendCode(@Body('email') email: string) {
    return this.usersService.resendVerificationEmail(email);
  }

 @UseGuards(AuthGuard('jwt'))
  @Patch('update-profile')
  async updateProfile(@Req() req: any, @Body() updateUserDto: UpdateUserDto) {
    const id_usuario = req.user.id_usuario;
    
    // Si viene nueva contraseña, validar la actual
    if (updateUserDto.passw) {
      if (!updateUserDto.contrasenaActual) {
        throw new BadRequestException('Debes proporcionar tu contraseña actual');
      }
      
      // Obtener el usuario con su contraseña actual
      const user = await this.usersService.findUserById(id_usuario);
      
      // Verificar que la contraseña actual sea correcta
      const isPasswordValid = await bcrypt.compare(updateUserDto.contrasenaActual, user.passw);
      
      if (!isPasswordValid) {
        throw new BadRequestException('La contraseña actual es incorrecta');
      }
      
      // Eliminar la contraseña actual del DTO para no guardarla
      delete updateUserDto.contrasenaActual;
    }
    
    return this.usersService.updateUserProfile(id_usuario, updateUserDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Req() req: any) {
    console.log('req.user completo:', req.user); // Para depurar
    
    if (!req.user) {
      throw new BadRequestException('Usuario no autenticado');
    }
    
    const id_usuario = req.user.id_usuario;
    
    if (!id_usuario) {
      console.error('req.user no contiene id_usuario:', req.user);
      throw new BadRequestException('Token inválido: no se encontró ID de usuario');
    }
    
    console.log('ID de usuario extraído:', id_usuario);
    return this.usersService.getProfile(id_usuario);
  }

  @Post('refresh-token')
  async refreshToken(
    @Body() body: RefreshTokenDto,
    @Req() req: any,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = this.getRefreshTokenFromRequest(req, body.refreshToken);
    if (!refreshToken) {
      throw new BadRequestException('Refresh token no proporcionado');
    }

    const tokens = await this.usersService.refreshToken(
      refreshToken,
      this.getSessionContext(req),
    );

    this.setAuthCookies(res, tokens);
    return tokens;
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('verify-user-email')
  async verifyUserEmail(@Body('email') email: string) {
    return this.usersService.verifyUserEmail(email);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('verify-user-token')
  async verifyUserToken(@Body('email') email: string, @Body('token') token: string) {
    return this.usersService.verifyUserToken(email, token);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('reset-psw')
  async resetPsw(@Body('email') email: string, @Body('psw') psw: string, @Body('token') token: string) {
    return this.usersService.resetPsw(email, psw, token);
  }

  @Post('auth/google-login')
  async loginGoogle(
    @Body() body: GoogleLoginDto,
    @Req() req: any,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.usersService.loginWithGoogle(
      body.idToken,
      this.getSessionContext(req, body.deviceName),
    );

    this.setAuthCookies(res, tokens);
    return tokens;
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  async logout(@Req() req: any, @Res({ passthrough: true }) res: Response) {
    this.clearAuthCookies(res);
    return this.usersService.logout(req.user.sessionId);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-recent-users-created')
  async getRecentUsersCreated() {
    return this.usersService.getRecentUsersCreated();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-roles')
  async getRoles() {
    return this.usersService.getRoles();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-users')
  async getUsers() {
    return this.usersService.getUsers();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Patch('update-user')
  updateUserStatus(@Body() updateData: UpdateUserDto) {
    return this.usersService.updateUserStatus(updateData);
  }
}
