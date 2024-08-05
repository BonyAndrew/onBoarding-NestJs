import { Module } from '@nestjs/common';
import { ProductsService } from './products.service';
import { ProductsController } from './products.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Products } from './entities/product.entity';
import { User } from 'src/users/entities/user.entity';
import { Role } from 'src/roles/entities/role.entity';
import { Permission } from 'src/permissions/entities/permission.entity';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { UsersModule } from 'src/users/users.module';
import { JwtService } from '@nestjs/jwt';

@Module({
  imports: [
    TypeOrmModule.forFeature([Products, User, Role, Permission]),
    UsersModule,
    
  ],
  providers: [ProductsService, JwtAuthGuard, JwtService],
  controllers: [ProductsController]
})
export class ProductsModule { }
