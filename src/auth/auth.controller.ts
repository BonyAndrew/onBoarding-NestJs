import { Controller, Post, UseGuards, Body, Req, Res, HttpStatus, Ip, Delete, Get, UnauthorizedException, BadRequestException, Param, NotFoundException, Session, HttpCode, HttpException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { LoginUserDto } from 'src/users/dto/login-user.dto';
import RefreshTokenDto from 'src/users/dto/refresh-token.dto';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { Request } from 'express';
import { SignUpUserDto } from 'src/users/dto/signup-user.dto';
import { UpdatePasswordDto } from 'src/users/dto/update-password.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { User } from 'src/users/entities/user.entity';
import { AuthGuard } from '@nestjs/passport';
import * as bcrypt from 'bcrypt';
import { ProfileDto } from 'src/users/dto/profile-user.dto';

@Controller('auth')
export class AuthController {

  constructor(
    private readonly userService: UsersService,
    private readonly authService: AuthService,
    private jwtService: JwtService
  ) { }

  @Post('login')
  async login(@Body() credentials: LoginUserDto) {
    console.log('credentials', credentials);
    try {
      return this.userService.login(credentials);
    } catch (e) {
      return new BadRequestException(e);
    }

  }//✅

  @Post('register')
  async register(@Body() body: SignUpUserDto, id) {
    const { name, email, password } = body;

    try {
      const newUser = await this.userService.register(id, name, email, password);
      await this.userService.sendValidationEmail(newUser.token, name, newUser.email);
      return ("enregistré avec succès");
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new BadRequestException(error);
      }
    }
  }//✅

  @Post('update-profile')
  @UseGuards()
  async updateUserProfile(@Body() profilDto: ProfileDto): Promise<User> {
    try {
      const user = await this.userService.findByEmail(profilDto.emailU);

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      if (profilDto.emailU) { user.email = profilDto.emailU; }
      if (profilDto.name) { user.name = profilDto.name; }
      if (profilDto.password) {
        user.password = await this.userService.hashPassword(profilDto.password);
      }

      const updatedUser = await this.userService.update(user.email, user);
      return updatedUser;
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      } else {
        throw new HttpException('Internal server error', HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }
  }//✅

  @Post('update-password/:id')
  async updatePassword(@Body() updatePasswordDto: UpdatePasswordDto, @Param('id') id) {
    try {
      const user = await this.userService.findOne(id);
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
      const isPasswordMatch = await bcrypt.compare(updatePasswordDto.oldPassword, user.password);
      console.log(isPasswordMatch);
      if (isPasswordMatch) {
        throw new Error("Votre ancien mot de passe est erroné!");
      }
      await this.userService.updatePassword(id, updatePasswordDto);
      return "votre mot de passe a été modifié!";
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      console.error(error);
      throw new HttpException('Une erreur s\'est produite lors de la mise à jour du mot de passe', HttpStatus.INTERNAL_SERVER_ERROR, error);
    }
  }//✅

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
  }//✅

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
  }//✅

  @Post('logout')
  async logout(@Req() req) {
    // Ici, vous pouvez ajouter de la logique supplémentaire, par exemple pour logger un événement de déconnexion ou invalider un token de rafraîchissement.
    req.logout();
    return { message: 'Déconnexion réussie' };
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
  }//✅

  @Get('verify/:token')
  async verifyEmail(@Param('token') token: string) {
    console.log('token: ', token);

    const decoded = await this.jwtService.verify(token);

    const userEmail = decoded.email;
    const user = await this.userService.findByEmail(userEmail);

    if (!user) {
      throw new NotFoundException('user not found');
    }

    if (!user.isValidated) {
      user.isValidated = true;
      await this.userService.update(userEmail, user);
    }

    return { user };

  }//✅
}
