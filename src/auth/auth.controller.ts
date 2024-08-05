import { Controller, Post, UseGuards, Body, Req, Res, HttpStatus, Get, UnauthorizedException, BadRequestException, Param, NotFoundException, HttpException, Session, InternalServerErrorException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { LoginUserDto } from 'src/users/dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { SignUpUserDto } from 'src/users/dto/signup-user.dto';
import { UpdatePasswordDto } from 'src/users/dto/update-password.dto';
import { User } from 'src/users/entities/user.entity';
import * as bcrypt from 'bcrypt';
import { ProfileDto } from 'src/users/dto/profile-user.dto';
import { Request, response, Response } from 'express';
import { LocalAuthGuard } from 'src/guards/localAuth.guard';
import { AuthGuard } from '@nestjs/passport';
import { Role } from 'src/roles/entities/role.entity';
import { permission } from 'process';

@Controller('auth')
export class AuthController {

  constructor(
    private readonly userService: UsersService,
    private readonly authService: AuthService,
    private jwtService: JwtService
  ) { }

  @Post('login')
  async login(@Body() credentials: LoginUserDto, @Req() req, @Session() session) {
    try {
      await this.userService.login(req.body);
  
      return {
        user: session.user,
      };
    } catch (e) {
      return new BadRequestException(e);
    }
  }//✅
  
  @UseGuards(LocalAuthGuard)
  @Post('auth/login')
  async signIn(@Req() req, @Session() session) {
    const { email, password } = req.body;
    
    const user = await this.userService.findByEmail(email);  

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Wrong password!');
    }

    if (!user.isValidated) {
      throw new BadRequestException('Your account is not validated');
    }

    const payload = {
      sub: user.id,
      username: user.name,
      email: user.email,
      role: user.role
    };
    const accessToken = this.jwtService.sign({ payload });

    session.user = {
      id: user.id,
      name: user.name,
      role: user.role,
    };

    return {
      accessToken,
      user: session.user,
      payload
    };
  }

  @Post('register')
  async register(@Body() body: SignUpUserDto) {
    const { name, email, password } = body;

    try {
      const newUser = await this.userService.register(name, email, password);
      await this.userService.sendValidationEmail(newUser.token, name, email);
      return newUser.token;
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new BadRequestException(error);
      }
    }
  }//✅

  @Post('update-profile/:id')
  @UseGuards()
  async updateUserProfile(@Param('id') id: string, @Body() profilDto: ProfileDto): Promise<User> {
    try {
      const user = await this.userService.findOne(id);

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      if (profilDto.emailU) { user.email = profilDto.emailU; }
      if (profilDto.name) { user.name = profilDto.name; }

      const updatedUser = await this.userService.update(user.email, user);
      return updatedUser;
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      } else {
        console.log(error)
        throw new HttpException('non', HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }
  }//✅

  @Post('update-password/:id')
  async updatePassword(@Body() updatePasswordDto: UpdatePasswordDto, @Param('id') id: string): Promise<string> {
    const user = await this.userService.findOne(id);

    // Vérifie si l'utilisateur existe
    if (!user) {
      throw new NotFoundException('Utilisateur non trouvé');
    }

    // Vérifie si l'ancien mot de passe correspond
    const isPasswordMatch = await bcrypt.compare(updatePasswordDto.oldPassword, user.password);
    console.log(user.password);
    console.log(isPasswordMatch);

    if (!isPasswordMatch) {
      throw new BadRequestException('Votre ancien mot de passe est erroné!');
    }

    try {
      await this.userService.updatePassword(id, updatePasswordDto);
      return 'Votre mot de passe a été modifié!';
    } catch (error) {
      console.error(error);
      throw new InternalServerErrorException('Une erreur s\'est produite lors de la mise à jour du mot de passe');
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
  
  @UseGuards()
  @Get('profile-tk')
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

    const decoded = await this.jwtService.verifyAsync(token);
    if (!decoded) {
      return null;
    }

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

  @Get('profile')
  @UseGuards(LocalAuthGuard)
  async getProfile(@Req() req: Request, @Res() response: Response) {
    // const user = await this.authService.getUserById(req.session.user.id);
    const user = await this.authService.getUserById(req.session.user);
    console.log("user :", user);
    if (!user) {
      return response.status(404).send();
    }
    return response.json(user);
  }//✅❌

  @Get('logout')
  async logout(@Req() req: Request, @Res() res: Response): Promise<void> {
    req.session.destroy((err) => {
      if (err) {
        console.log('Erreur:', err);
      }
      res.clearCookie('connect.sid');
      // res.redirect(''); 
    });
  }//✅

  // @Get('check-session')
  // checkSession(@Session() session) {
  //   if (session && session.user) {
  //     return { status: 'La session est ouverte' };
  //   } else {
  //     return { status: 'Aucune session ouverte' };
  //   }
  // }//❌
}
