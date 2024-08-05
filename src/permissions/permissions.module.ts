import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PermissionsService } from './permissions.service';
import { PermissionsController } from './permissions.controller';
import { Permission } from './entities/permission.entity';
import { RolesModule } from 'src/roles/roles.module';
import { Role } from 'src/roles/entities/role.entity';

@Module({
    imports: [
        TypeOrmModule.forFeature([Permission, Role]),
        
    ],
    providers: [PermissionsService],
    controllers: [PermissionsController],
    exports: [PermissionsService, TypeOrmModule],
})
export class PermissionsModule { }
