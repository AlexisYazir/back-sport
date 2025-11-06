import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  UseGuards,
  Patch,
  Req,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

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

  @Get('verify-email')
  async verifyEmail(@Query('token') token: string) {
    return this.usersService.verifyEmail(token);
  }

  @UseGuards(AuthGuard('jwt'))
  @Patch('update-profile')
  async updateProfile(@Req() req: any, @Body() updateUserDto: UpdateUserDto) {
    const id_usuario = req.user.id_usuario;
    return this.usersService.updateUserProfile(id_usuario, updateUserDto);
  }
}
