import { Body, Controller, Delete, Get, Param, ParseIntPipe, Patch, Post, Put, UseGuards } from '@nestjs/common';
import { Role } from './entities/role.entity';
import { RolesService } from './roles.service';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import { Roles } from 'src/decorators/roles.decorator';
import { RolesGuard } from 'src/guards/role.guard';
import { AssignPermissionsDto } from './dto/assign-permission.dto';
import { Permission } from 'src/permissions/entities/permission.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

@Controller('roles')
export class RolesController {
  constructor(
    private readonly rolesService: RolesService,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>
  ) {}

  @Post()
  create(@Body() createRole: CreateRoleDto): Promise<Role> {
    return this.rolesService.create(createRole);
  }
  
  @Get()
  findAll(): Promise<Role[]> {
    return this.rolesService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: number): Promise<Role> {
    return this.rolesService.findOne(id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateRoleDto: UpdateRoleDto) {
    return this.rolesService.update(+id, updateRoleDto);
  }

  @Delete(':id')
  remove(@Param('id') id: number): Promise<void> {
    return this.rolesService.remove(id);
  } 
}


