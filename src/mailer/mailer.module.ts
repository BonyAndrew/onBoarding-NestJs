import { MailerModule } from '@nestjs-modules/mailer';
import { Module } from '@nestjs/common';
import { MailService } from './mailer.service';
import { MailerController } from './mailer.controller';
import { UsersModule } from 'src/users/users.module';

@Module({
  imports: [
    MailerModule.forRootAsync({
      useFactory: () => ({
        transport: {
          host: 'smtp.ionos.com',
          port: 587,
          secure: false,
          auth: {
            user: 'contact@socecepme.com',
            pass: 'Contact@2020',
          },
        },
        defaults: {
          from: '"AD Dev<🐒/" <contact@socecepme.com>',
        },
      }),
    }),
    UsersModule
  ],
  providers: [MailService],
  exports: [MailService],
  controllers: [MailerController],
})
export class MailModule { }
