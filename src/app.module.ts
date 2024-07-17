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
import { RolesGuard } from './autorization/roles.guard';
// import { MessageResolver } from './message/message.resolver';


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
  ],
  controllers: [AppController],
  providers: [
    AppService, 
    // MessageResolver
    {
      provide: "APP_GUARD",
      useClass: RolesGuard,
    },
  ],
})
export class AppModule { }
