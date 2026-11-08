/* eslint-disable */
import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { UpdateUserDto } from '../dto/update-user.dto';
import { Roles } from '../entities/roles.entity';
import { User } from '../entities/user.entity';
import { AccountDeletionAccessService } from '../../account-deletion/account-deletion-access.service';

@Injectable()
export class UserAdminService {
  private readonly logger = new Logger(UserAdminService.name);

  constructor(
    @InjectRepository(User, 'readerConnection')
    private readonly userReaderRepository: Repository<User>,
    @InjectRepository(User, 'adminConnection')
    private readonly userAdminRepository: Repository<User>,
    @InjectRepository(Roles, 'editorConnection')
    private readonly rolesRepository: Repository<Roles>,
    private readonly accountDeletionAccess: AccountDeletionAccessService,
  ) {}

  async getRecentUsersCreated(): Promise<any[]> {
    try {
      const result = await this.userReaderRepository.query(
        `SELECT * FROM core.get_recients_users();`,
      );

      return result;
    } catch (error) {
      this.logger.error('Recent accounts query failed');
      throw error;
    }
  }

  async getRoles(): Promise<Roles[]> {
    return await this.rolesRepository.find();
  }

  async getUsers(): Promise<User[]> {
    return await this.userReaderRepository.find();
  }

  async updateUserStatus(updateData: UpdateUserDto) {
    const user = await this.userReaderRepository.findOne({
      where: { id_usuario: updateData.id_usuario },
    });

    if (!user) {
      throw new BadRequestException('Usuario no encontrado');
    }

    return this.accountDeletionAccess.withAccountLock(
      user.id_usuario,
      async (manager, currentUser) => {
        currentUser.rol = updateData.rol ?? currentUser.rol;
        currentUser.activo = updateData.activo ?? currentUser.activo;
        return manager.getRepository(User).save(currentUser);
      },
      this.userAdminRepository.manager,
    );
  }

  async deleteUser(id_usuario: number): Promise<{ message: string }> {
    const user = await this.userReaderRepository.findOne({
      where: { id_usuario },
    });

    if (!user) {
      throw new BadRequestException('Usuario no encontrado');
    }

    await this.accountDeletionAccess.withAccountLock(
      id_usuario,
      async (manager) => {
        await manager.getRepository(User).delete(id_usuario);
      },
      this.userAdminRepository.manager,
    );

    return { message: 'Usuario eliminado correctamente' };
  }
}
