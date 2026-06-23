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
import { UserAccountService } from './services/user-account.service';
import { UserAdminService } from './services/user-admin.service';
import { UserGoogleAuthService } from './services/user-google-auth.service';
import { UserPasswordRecoveryService } from './services/user-password-recovery.service';
import { UserSessionService } from './services/user-session.service';

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
  providers: [
    UsersService,
    UserAccountService,
    UserSessionService,
    UserPasswordRecoveryService,
    UserGoogleAuthService,
    UserAdminService,
    JwtStrategy,
  ],
  exports: [UsersService],
})
export class UsersModule {}
