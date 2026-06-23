/* eslint-disable */
import { Injectable } from '@nestjs/common';

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Roles } from './entities/roles.entity';
import { User } from './entities/user.entity';
import { UserAccountService } from './services/user-account.service';
import { UserAdminService } from './services/user-admin.service';
import { UserGoogleAuthService } from './services/user-google-auth.service';
import { UserPasswordRecoveryService } from './services/user-password-recovery.service';
import {
  SessionContext,
  UserSessionService,
} from './services/user-session.service';

@Injectable()
export class UsersService {
  constructor(
    private readonly accountService: UserAccountService,
    private readonly sessionService: UserSessionService,
    private readonly passwordRecoveryService: UserPasswordRecoveryService,
    private readonly googleAuthService: UserGoogleAuthService,
    private readonly adminService: UserAdminService,
  ) {}

  isSessionActive(sessionId: string): Promise<boolean> {
    return this.sessionService.isSessionActive(sessionId);
  }

  logout(sessionId: string): Promise<{ message: string }> {
    return this.sessionService.logout(sessionId);
  }

  createUser(createUserDto: CreateUserDto): Promise<User> {
    return this.accountService.createUser(createUserDto);
  }

  verifyEmail(
    email: string,
    token: string,
  ): Promise<{ message: string }> {
    return this.accountService.verifyEmail(email, token);
  }

  resendVerificationEmail(email: string): Promise<{ message: string }> {
    return this.accountService.resendVerificationEmail(email);
  }

  requestVerificationCode(email: string): Promise<{ message: string }> {
    return this.accountService.requestVerificationCode(email);
  }

  loginUser(email: string, passw: string, context: SessionContext) {
    return this.sessionService.loginUser(email, passw, context);
  }

  refreshToken(refreshToken: string, context: SessionContext) {
    return this.sessionService.refreshToken(refreshToken, context);
  }

  restoreSessionFromAccessToken(
    accessToken: string,
    context: SessionContext,
  ) {
    return this.sessionService.restoreSessionFromAccessToken(
      accessToken,
      context,
    );
  }

  getProfile(id_usuario: number) {
    return this.accountService.getProfile(id_usuario);
  }

  updateUserProfile(id_usuario: number, dto: UpdateUserDto) {
    return this.accountService.updateUserProfile(id_usuario, dto);
  }

  findUserById(id_usuario: number): Promise<User> {
    return this.accountService.findUserById(id_usuario);
  }

  verifyUserEmail(email: string) {
    return this.passwordRecoveryService.verifyUserEmail(email);
  }

  verifyUserToken(
    email: string,
    token: string,
  ): Promise<{ message: string }> {
    return this.passwordRecoveryService.verifyUserToken(email, token);
  }

  resetPsw(
    email: string,
    psw: string,
    token: string,
  ): Promise<{ message: string }> {
    return this.passwordRecoveryService.resetPsw(email, psw, token);
  }

  loginWithGoogle(idToken: string, context: SessionContext) {
    return this.googleAuthService.loginWithGoogle(idToken, context);
  }

  getRecentUsersCreated(): Promise<any[]> {
    return this.adminService.getRecentUsersCreated();
  }

  getRoles(): Promise<Roles[]> {
    return this.adminService.getRoles();
  }

  getUsers(): Promise<User[]> {
    return this.adminService.getUsers();
  }

  updateUserStatus(updateData: UpdateUserDto) {
    return this.adminService.updateUserStatus(updateData);
  }

  deleteUser(id_usuario: number): Promise<{ message: string }> {
    return this.adminService.deleteUser(id_usuario);
  }
}
