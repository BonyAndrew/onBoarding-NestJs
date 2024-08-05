import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DatabaseModule } from './database.module';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { JwtModule } from '@nestjs/jwt';
import { MailModule } from './mailer/mailer.module';
import { PassportModule } from '@nestjs/passport';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { ProductsModule } from './products/products.module';
import { RolesModule } from './roles/roles.module';
import { PermissionsController } from './permissions/permissions.controller';
import { PermissionsService } from './permissions/permissions.service';
import { PermissionsModule } from './permissions/permissions.module';
import { RolesGuard } from './guards/role.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesService } from './roles/roles.service';
import { AuthService } from './auth/auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { PermissionGuard } from './guards/permission.guard';
import { User } from './users/entities/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthGuard } from './guards/auth.guard';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET,
    }),
    DatabaseModule,
    UsersModule,
    AuthModule,
    MailModule,
    PassportModule.register({ defaultStrategy: 'local' }),
    ClientsModule.register([
      {
        transport: Transport.RMQ,
        options: {
          urls: ['amqp://localhost'],
          queue: 'chat',
        },
        name: 'andrew',
      }

    ]),
    ProductsModule,
    RolesModule,
    PermissionsModule,
    TypeOrmModule.forFeature([User]),
  ],
  controllers: [AppController, PermissionsController],
  providers: [
    AppService,
    PermissionsService,
    AuthGuard,
    PermissionGuard,
    RolesGuard,
    JwtAuthGuard,
    RolesService,
    AuthService,
    JwtStrategy,
    JwtModule,
  ],
  exports: [JwtModule]
})
export class AppModule { }
