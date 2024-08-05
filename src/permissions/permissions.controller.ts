import { Body, Controller, Delete, Get, Param, Patch, Post } from '@nestjs/common';
import { PermissionsService } from './permissions.service';
import { Permission } from './entities/permission.entity';
import { CreatePermissionDto } from './dto/create-permission.dto';
import { UpdatePermissionDto } from './dto/update-permission.dto';

@Controller('permissions')
export class PermissionsController {
    constructor(private readonly permissionService: PermissionsService) {}

  @Get()
  findAll(): Promise<Permission[]> {
    return this.permissionService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string): Promise<Permission> {
    return this.permissionService.findOne(id);
  }

  @Post()
  create(@Body() createPermissionsDto: CreatePermissionDto): Promise<Permission> {
    return this.permissionService.create(createPermissionsDto);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updatePermissionsDto: UpdatePermissionDto): Promise<Permission> {
    return this.permissionService.update(+id, updatePermissionsDto);
  }

  @Delete(':id')
  remove(@Param('id') id): Promise<any> {
    return this.permissionService.remove(id);
  }

  // assigner les permissions a un rôle
  @Post('assign-permissions')
  async assignPermissions(
    @Body('roleId') roleId: number,
    @Body('permissionIds') permissionIds: number[],
  ) {
    return await this.permissionService.assignPermissionsToRole(roleId, permissionIds);
  }
}

