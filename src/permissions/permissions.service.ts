import { Injectable, NotFoundException } from '@nestjs/common';
import { Permission } from './entities/permission.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { FindOneOptions, FindOptionsWhere, Repository } from 'typeorm';
import { CreatePermissionDto } from './dto/create-permission.dto';
import { UpdatePermissionDto } from './dto/update-permission.dto';
import { User } from 'src/users/entities/user.entity';
import { Role } from 'src/roles/entities/role.entity';

@Injectable()
export class PermissionsService {
  constructor(
    // private readonly permissionRepository: permissionRepository,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
  ) { }

  findAll(): Promise<Permission[]> {
    return this.permissionRepository.find();
  }

  async findOne(permissionId): Promise<Permission> {
    const options: FindOneOptions<Permission> = {
      where: {
        permissionId: permissionId,
      } as FindOptionsWhere<Permission>,
    };
    if (!options) {
      console.log('aucun trouvé');
      throw new NotFoundException();
    }
    return await this.permissionRepository.findOne(options);
  }

  async remove(id) {
    const permission = await this.findOne(id);
    if (!permission) {
      throw new NotFoundException();
    }

    return await this.permissionRepository.remove(permission);
  }

  async create(createPermissionDto: CreatePermissionDto): Promise<Permission> {
    const permission = new Permission();
    permission.name = createPermissionDto.name;
    return this.permissionRepository.save(permission);
  }

  async update(permissionId, updatePermissionDto: UpdatePermissionDto) {
    const permission = await this.findOne(permissionId);
    console.log(permission);

    if (!permission) {
      throw new NotFoundException();
    }

    Object.assign(permission, updatePermissionDto);

    return await this.permissionRepository.save(permission);
  }

  // ancien code
  async assignPermissionsToRole(roleId: number, permissionIds: number[]): Promise<Role> {
    const role = await this.roleRepository.findOne({
      where: { id: roleId },
      relations: ['permissions'],
    });

    if (!role) {
      throw new Error('Role not found');
    }

    const permissions = await this.permissionRepository.findByIds(permissionIds);

    if (role && permissions) {
      role.permissions = permissions;
      return await this.roleRepository.save(role);
    }
    throw new Error('Role or Permissions not found');
  }
}
