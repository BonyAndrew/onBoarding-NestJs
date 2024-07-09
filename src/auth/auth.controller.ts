import { Controller, Post, UseGuards, Body, Req, Res, HttpStatus, Ip, Delete, Get, UnauthorizedException, BadRequestException, Param, NotFoundException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { LoginUserDto } from 'src/users/dto/login-user.dto';
import RefreshTokenDto from 'src/users/dto/refresh-token.dto';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { Request } from 'express';
import { SignUpUserDto } from 'src/users/dto/signup-user.dto';

@Controller('auth')
export class AuthController {

  constructor(
    private readonly userService: UsersService,
    private readonly authService: AuthService,
    private jwtService: JwtService
  ) { }

  @Post('login')
  async login(@Body() credentials: LoginUserDto, @Req() request, @Ip() ip: string) {
    return this.userService.login(credentials);
  }

  @Post('register')
  async register(@Body() body: SignUpUserDto, id) {
    const { name, email, password } = body;

    try {
      const newUser = await this.userService.register(id, name, email, password);
      await this.userService.sendValidationEmail(newUser.token, name, newUser.email);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new BadRequestException(error);
      }
    }
  }

  @Post('refresh')
  async refreshToken(@Body() body: RefreshTokenDto) {
    return this.userService.refresh(body.refreshToken);
  }

  @Delete('logout')
  async logout(@Body() body: RefreshTokenDto) {
    return this.userService.logout(body.refreshToken);
  }

  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string, @Res() res) {
    try {
      const user = await this.userService.findByEmail(email);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      await this.userService.sendResetPasswordEmail(user);

      res.status(HttpStatus.OK).json({
        message: 'Please check your mailbox',
      });
    } catch (error) {
      if (error instanceof NotFoundException) {
        res.status(HttpStatus.NOT_FOUND).json({
          message: 'User not found',
        });
      } else {
        console.error('Error sending forgot password email:', error);
        res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
          message: 'Error sending reset password email',
        });
      }
    }
  }

  @Post('reset-password')
  async resetPassword(@Body() { token, newPassword }: { token: string; newPassword: string }, @Res() res) {
    try {
      const user = await this.userService.validateResetPasswordToken(token);
      if (!user) {
        throw new BadRequestException('Invalid or expired token');
      }

      await this.userService.resetPassword(user, newPassword);
      await this.userService.sendResetPasswordSuccessEmail(user);

      res.status(HttpStatus.OK).json({
        message: 'Password reset successfully',
      });
    } catch (error) {
      if (error instanceof BadRequestException) {
        res.status(HttpStatus.BAD_REQUEST).json({
          message: 'Invalid or expired token',
        });
      } else {
        console.error('Error resetting password:', error);
        res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
          message: 'Error resetting password',
        });
      }
    }
  }

  @UseGuards()
  @Get('profile')
  async profile(@Req() req: Request) {

    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      throw new UnauthorizedException('No token found!');
    }

    const token = authHeader.split(' ')[1];
    try {
      const userInfo = await this.userService.getUserInfo(token);
      return userInfo;
    } catch (error) {
      throw new UnauthorizedException('Invalid Token');
    }
  }

  @Get('verify/:token')
  async decodeToken(@Param('token') token: string) {
    console.log('token: ', token);

    const decoded = this.jwtService.verify(token);
    console.log(decoded);

    const userId = decoded.id;

    const user = await this.userService.findOne(userId);
    console.log('is:', user)

    if (!userId) {
      throw new NotFoundException('user not found');
    }
    if (!user.isValidated) {
      user.isValidated = true;
      await this.userService.update(userId, user);
    }

    return { user };
  }

  // @Patch('reset-password/:token')
  // async resetPassword(
  //   @Param('token') token: string,
  //   @Body('newPassword') newPassword: string
  // ) {
  //   await this.authService.resetPassword(token, newPassword);
  //   return { message: 'Votre mot de passe a été réinitialisé avec succès.' };
  // }
}
