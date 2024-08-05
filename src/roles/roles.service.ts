import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { EntityManager, Repository } from 'typeorm';
import { Role } from './entities/role.entity';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import { Permission } from 'src/permissions/entities/permission.entity';
import { User } from 'src/users/entities/user.entity';

@Injectable()
export class RolesService {
  constructor(
    @InjectRepository(Role)
    private RolesRepository: Repository<Role>,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
  ) { }

  create(createRoles: CreateRoleDto): Promise<Role> {
    const roles = new Role();
    roles.name = createRoles.name;
    return this.RolesRepository.save(roles);
  }//✅

  async findAll(): Promise<Role[]> {

    return this.RolesRepository.find({ relations: ['permissions'] });
  }//✅

  findOne(id): Promise<Role> {
    return this.RolesRepository.findOneBy(id);
  }//✅

  async update(id: number, updateRoleDto: UpdateRoleDto) {
    const roleU = await this.findOne(id);
    if (!roleU) {
      throw new NotFoundException();
    }

    Object.assign(roleU, updateRoleDto);

    return await this.RolesRepository.save(roleU);
  }//✅

  async remove(id: number): Promise<void> {
    await this.RolesRepository.delete(id);
  }//✅

  async getRole(id): Promise<Role> {
    return this.RolesRepository.findOne(id);
  }
}
