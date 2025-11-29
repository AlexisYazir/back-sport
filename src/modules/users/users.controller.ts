/* eslint-disable */
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { UsersService } from './users.service';
import { AuthGuard } from '@nestjs/passport';
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
    return this.usersService.createUser(createUserDto);
  }

  @Post('login-user')
  async loginUser(@Body() loginUserDto: LoginUserDto) {
    return this.usersService.loginUser(loginUserDto);
  }

  @Get('verify-email/:token')
  async verifyEmail(@Param('token') token: string) {
    return this.usersService.verifyEmail(token);
  }

  @UseGuards(AuthGuard('jwt'))
  @Patch('update-profile')
  async updateProfile(@Req() req: any, @Body() updateUserDto: UpdateUserDto) {
    const id_usuario = req.user.id_usuario;
    return this.usersService.updateUserProfile(id_usuario, updateUserDto);
  }

  @Post('verify-user-email')
  async verifyUserEmail(@Body('email') email: string) {
    return this.usersService.verifyUserEmail(email);
  }

  @Post('verify-user-token')
  async verifyUserToken(
    @Body('email') email: string,
    @Body('token') token: string,
  ) {
    return this.usersService.verifyUserToken(email, token);
  }

  @Post('reset-psw')
  async resetPsw(@Body('email') email: string, @Body('psw') psw: string) {
    return this.usersService.resetPsw(email, psw);
  }

  // @Post('login-google')
  // async loginGoogle(@Body('idToken') idToken: string) {
  //   return this.usersService.loginWithGoogle(idToken);
  // }
}
