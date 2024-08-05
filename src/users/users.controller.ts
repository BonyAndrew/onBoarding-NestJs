import { Body, Controller, Delete, Get, NotFoundException, Param, Patch, Post, Put, UseGuards } from "@nestjs/common";
import { User } from "./entities/user.entity";
import { UsersService } from "./users.service";
import { CreateUserDto } from "./dto/create-user.dto";
import { UpdateUserDto } from "./dto/update-user.dto";
import { JwtAuthGuard } from "src/guards/jwt-auth.guard";
import { RolesGuard } from "src/guards/role.guard";
import { Roles } from "src/decorators/roles.decorator";
import { RequirePermissions } from "src/decorators/permission.decorator";
import { AuthService } from "src/auth/auth.service";
import { RolesService } from "src/roles/roles.service";

@Controller('users')
// @UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private authService: AuthService,
    private roleService: RolesService
  ) {}

  @Get()
  findAll(): Promise<User[]> {
    return this.usersService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string): Promise<User> {
    return this.usersService.findOne(id);
  }

  @Post()
  // @Roles()
  create(@Body() createUserDto: CreateUserDto): Promise<User[]> {
    return this.usersService.create(createUserDto);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto): Promise<User> {
    return this.usersService.update(+id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id): Promise<any> {
    return this.usersService.remove(id);
  }

  //assigner à un utilisateur un rôle par son identifiant en utilisant la mise à jour 
  @Patch(':id/role')
  async assignRoleToUser(
    @Param('id') userId: number,
    @Body('roleId') roleId: number,
  ) {
    return this.usersService.assignRoleToUser(userId, roleId);
  }

  //assigner à un utilisateur un rôle par son identifiant
  @Post(':id/role')
  async assignRole(@Param('id') userId: number, @Body() body: { roleId: number }) {
    const user = await this.usersService.findOne(userId);
    user.role = await this.roleService.findOne(body.roleId);
    return this.usersService.save(user);
  }

  //verifie si un utilisateur a une permission spécifique
  @Get(':id/has-permission/:permissionName')
  async checkPermission(@Param('id') userId: number, @Param('permissionName') permissionName: string) {
    return this.authService.userHasPermission(userId, permissionName);
  }

  //affiche toutes les permissions d'un utilisateur 
  @Get(':id/permissions')
  async getUserWithPermissions(@Param('id') userId: number) {
    const user = await this.usersService.getUserWithPermissions(userId);
    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }
    return user;
  }
}
