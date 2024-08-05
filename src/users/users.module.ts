import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { User } from './entities/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { RolesModule } from 'src/roles/roles.module';
import { AuthModule } from 'src/auth/auth.module';
import { AuthService } from 'src/auth/auth.service';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    RolesModule,
    AuthModule,
    JwtModule
],
  controllers: [UsersController],
  providers: [UsersService, AuthService],
  exports: [UsersService,]
})
export class UsersModule {}
