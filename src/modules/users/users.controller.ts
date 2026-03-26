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
} from '@nestjs/common';

interface SessionContext {
  ipAddress: string | null;
  userAgent: string | null;
  deviceName?: string;
}

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

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
  ) {
    return this.usersService.loginUser(
      email,
      passw,
      this.getSessionContext(req, deviceName),
    );
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
  async refreshToken(@Body() body: RefreshTokenDto, @Req() req: any) {
    return this.usersService.refreshToken(
      body.refreshToken,
      this.getSessionContext(req),
    );
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
  async loginGoogle(@Body() body: GoogleLoginDto, @Req() req: any) {
    return this.usersService.loginWithGoogle(
      body.idToken,
      this.getSessionContext(req, body.deviceName),
    );
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  async logout(@Req() req: any) {
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
