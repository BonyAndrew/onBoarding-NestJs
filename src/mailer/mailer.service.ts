import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import jwt, { sign } from 'jsonwebtoken';
import { StringifyOptions } from 'querystring';

@Injectable()
export class MailService {
  constructor(
    private readonly mailerService: MailerService,
    private userService: UsersService,
    private jwtService: JwtService,
  ) { }

  // async sendTokenEmail(
  //     email: string,
  //     //  token: string
  // ) {
  //     const token = process.env.EMAIL_SECRET;
  //     const mail = await this.mailerService.sendMail({
  //         to: email,
  //         subject: 'Votre Token',
  //         template: './templates/confirm.html',
  //         context: {
  //             url: `http://votreapp.com/confirm?token=${token}`
  //             // token: process.env.EMAIL_SECRET,
  //         },
  //     });
  //     return mail;
  // }

  // async sendValidationEmail(to: string, id: string) {
  //   const token= this.jwtService.sign({ id }, { expiresIn: '120s' });
  //   const subject = 'Validation Token';
  //   const body = `Votre token ${token} est en attente de validation.`;

  //   await this.mailerService.sendMail({
  //     to,
  //     subject,
  //     text: body,
  //     replyTo: null
  //   });
  // }
}
