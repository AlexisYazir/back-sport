/* eslint-disable */
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersService } from './users.service';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import * as bcrypt from 'bcrypt';
import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  Patch,
  Req,
  BadRequestException,
} from '@nestjs/common';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('create-user')
  async createUser(@Body() createUserDto: CreateUserDto) {
    console.log(createUserDto);
    return this.usersService.createUser(createUserDto);
  }

  @Post('login-user')
  async loginUser(@Body('email') email: string, @Body('passw') passw: string) {
    return this.usersService.loginUser(email, passw);
  }
  
  @Post('verify-email')
  async verifyEmail(@Body('email') email: string, @Body('token') token: string) {
    return this.usersService.verifyEmail(email, token);
  }

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
  async refreshToken(@Body('refreshToken') refreshToken: string) {
    return this.usersService.refreshToken(refreshToken);
  }

  @Post('verify-user-email')
  async verifyUserEmail(@Body('email') email: string) {
    return this.usersService.verifyUserEmail(email);
  }

  @Post('verify-user-token')
  async verifyUserToken(@Body('email') email: string, @Body('token') token: string) {
    return this.usersService.verifyUserToken(email, token);
  }

  @Post('reset-psw')
  async resetPsw(@Body('email') email: string, @Body('psw') psw: string) {
    return this.usersService.resetPsw(email, psw);
  }

  @Post('auth/google-login')
  async loginGoogle(@Body('idToken') idToken: string) {
    return this.usersService.loginWithGoogle(idToken);
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
