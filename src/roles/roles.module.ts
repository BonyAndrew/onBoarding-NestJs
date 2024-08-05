import { Module } from '@nestjs/common';
import { RolesService } from './roles.service';
import { RolesController } from './roles.controller';
import { Role } from './entities/role.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PermissionsModule } from 'src/permissions/permissions.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Role]), 
    PermissionsModule
  ],
  providers: [RolesService],
  controllers: [RolesController],
  exports: [RolesService, TypeOrmModule]
})
export class RolesModule {}
  