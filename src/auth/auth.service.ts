import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { MailerService } from '@nestjs-modules/mailer';
import { User } from 'src/users/entities/user.entity';

@Injectable()
export class AuthService {
    constructor(
        private jwtService: JwtService,
        private usersService: UsersService,
        private mailerService: MailerService
    ) { }

    async generateResetPasswordToken(user: User): Promise<string> {
        const payload = { userId: user.id, email: user.email };
        const token = await this.jwtService.signAsync(payload);
        return token;
    }

    async sendResetPasswordEmail(email: string, token: string) {
        const resetLink = `http://localhost:3000/auth/reset-password?token=${token}`;
    }

    async resetPassword(token: string, newPassword: string): Promise<void> {
        try {
            const decoded = this.jwtService.verify(token, {
                secret: process.env.JWT_RESET_PASSWORD_SECRET,
            });
            const email = decoded.email;
        } catch (error) {
            throw new Error('Invalid or expired reset token');
        }
    }
}
