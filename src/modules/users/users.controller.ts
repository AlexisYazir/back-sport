/* eslint-disable */
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersService } from './users.service';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  Patch,
  Req,
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
    return this.usersService.updateUserProfile(id_usuario, updateUserDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Req() req: any){
    const id_usuario = req.user.id_usuario;
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
