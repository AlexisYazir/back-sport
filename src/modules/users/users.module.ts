import { UsersController } from './users.controller';
import { PassportModule } from '@nestjs/passport';
import { MailModule } from '../../services/mail/mail.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { UserSession } from './entities/user-session.entity';
import { Roles } from './entities/roles.entity';
import { JwtStrategy } from '../../services/auth/jwt.strategy';
import { Module } from '@nestjs/common';

@Module({
  imports: [
    //  IMPORTANTE: Especificar las conexiones para CADA repositorio
    TypeOrmModule.forFeature([User, Roles, UserSession], 'editorConnection'),
    TypeOrmModule.forFeature([User, Roles, UserSession], 'readerConnection'),
    TypeOrmModule.forFeature([User, Roles], 'adminConnection'),
    PassportModule,
    MailModule,
  ],
  controllers: [UsersController],
  providers: [UsersService, JwtStrategy],
  exports: [UsersService],
})
export class UsersModule {}
