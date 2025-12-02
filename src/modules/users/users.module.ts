import { UsersController } from './users.controller';
import { PassportModule } from '@nestjs/passport';
import { MailModule } from '../../services/mail/mail.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { JwtStrategy } from './jwt.strategy';
import { Module } from '@nestjs/common';

@Module({
  imports: [TypeOrmModule.forFeature([User]), PassportModule, MailModule],
  controllers: [UsersController],
  providers: [UsersService, JwtStrategy],
  exports: [UsersService],
})
export class UsersModule {}
