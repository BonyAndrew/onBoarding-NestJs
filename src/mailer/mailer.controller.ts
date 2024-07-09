import { Body, Controller, Post } from '@nestjs/common';
import { MailService } from './mailer.service';

@Controller('mailer')
export class MailerController {
    constructor(
        private mailService: MailService,
    ) { }
    // @Post('send')
    // async sendEmail(@Body() mailData: { email: string }) {
    //     const { email } = mailData;
    //     return this.mailService.sendTokenEmail(email);
    // }

  // @Post('send')
  // async validate(@Body() user: any) {
  //   // generate a token or use the EMAIL_SECRET
  //   // const token = process.env.EMAIL_SECRET;

  //   await this.mailService.sendValidationEmail(user.email);

  //   return {
  //       message: 'Validation email sent successfully. Please check your email to validate your account.',
  //   }
  //   // return a response or redirect to a validation page
  // }
}
