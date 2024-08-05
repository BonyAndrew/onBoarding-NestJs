import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from 'src/auth/auth.service';
import { User } from 'src/users/entities/user.entity';

@Injectable()
export class LocalAuthGuard extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ emailField: 'email', passwordField: 'password' });
  }

  async validate(email: string, password: string): Promise<User> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}