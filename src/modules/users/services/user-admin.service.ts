/* eslint-disable */
import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { UpdateUserDto } from '../dto/update-user.dto';
import { Roles } from '../entities/roles.entity';
import { User } from '../entities/user.entity';

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
  ) {}

  async getRecentUsersCreated(): Promise<any[]> {
    try {
      const result = await this.userReaderRepository.query(
        `SELECT * FROM core.get_recients_users();`,
      );

      return result;
    } catch (error) {
      this.logger.error('ERROR REAL:', error);
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

    user.rol = updateData.rol ?? user.rol;
    user.activo = updateData.activo ?? user.activo;

    return await this.userAdminRepository.save(user);
  }

  async deleteUser(id_usuario: number): Promise<{ message: string }> {
    const user = await this.userReaderRepository.findOne({
      where: { id_usuario },
    });

    if (!user) {
      throw new BadRequestException('Usuario no encontrado');
    }

    await this.userAdminRepository.delete(id_usuario);

    return { message: 'Usuario eliminado correctamente' };
  }
}
