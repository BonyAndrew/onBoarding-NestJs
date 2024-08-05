import { BadRequestException, GoneException, HttpException, HttpStatus, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { FindOneOptions, FindOptionsWhere, MoreThanOrEqual, Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { getRepositoryToken, InjectRepository } from '@nestjs/typeorm';
import { UpdateUserDto } from './dto/update-user.dto';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import jwt, { sign } from 'jsonwebtoken';
import RefreshToken from 'src/auth/entities/refresh-token.entity';
import { v4 as uuidv4 } from 'uuid';
import { MailerService } from '@nestjs-modules/mailer';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { ProfileDto } from './dto/profile-user.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { Role } from 'src/roles/entities/role.entity';
import { RolesService } from 'src/roles/roles.service';
import { access } from 'fs';


@Injectable()
export class UsersService {

  private refreshTokens: RefreshToken[] = [];

  constructor(
    private jwtService: JwtService,
    private readonly mailerService: MailerService,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(User)
    private userRepository: Repository<User>
  ) { }

  async save(user: User): Promise<User> {
    return this.userRepository.save(user);
  }

  async getAll() {
    return getRepositoryToken(User);
  }//✅

  async findAllUsers(): Promise<User[]> {
    return await this.userRepository.find();
  }//✅

  // async findAll(): Promise<User[]> {
  //   return await this.userRepository.find(User);
  // }//✅
  async findAll(): Promise<User[]> {
    return this.userRepository.find({ relations: ['role', 'permissions'] });
  }

  async findOne(id): Promise<User> {
    const options: FindOneOptions<User> = {
      where: {
        id: id,
      } as FindOptionsWhere<User>,
    };
    if (!options) {
      throw new NotFoundException();
    }
    return await this.userRepository.findOne(options);
  }//✅

  async create(user): Promise<User[]> {
    return await this.userRepository.save(user);
  }//✅

  async createU(createUserDto: CreateUserDto): Promise<User> {
    const userC = new User();
    userC.name = createUserDto.name;
    userC.email = createUserDto.email;
    userC.password =createUserDto.password;
    
    return this.userRepository.save(userC);
  }//✅

  async createUser(user: User): Promise<User> {
    const userN = new User();
    userN.name = user.name;
    userN.email = user.email;
    userN.password = user.password;
    userN.token = user.token;
    // userN.roles = user.roles;
    return await this.userRepository.save(userN);
  }//✅

  async update(id, updateUserDto: UpdateUserDto) {
    const userU = await this.findOne(id);
    if (!userU) {
      throw new NotFoundException();
    }

    Object.assign(userU, updateUserDto);

    return await this.userRepository.save(userU);
  }//✅

  async remove(id: number) {
    const user = await this.findOne(id);
    if (!user) {
      throw new NotFoundException();
    }

    return await this.userRepository.remove(user);
  }//✅

  async register(name: string, email: string, password: string ) {

    const emailInUse = await this.userRepository.findOne({ where: { email } });

    // if (emailInUse) {
    //   throw new BadRequestException('This email is already used');
    // }

    const user = new User();
    const payload = { 
      name: name, 
      email: email,
    };
    const token = this.jwtService.sign({ payload }, { expiresIn: '24h' });

    user.name = name;
    user.email = email;
    user.password = password;
    user.token = token;

    console.log(user)
    return await this.userRepository.save(user);
  }//✅ 
 
  async login(credentials: LoginUserDto) {
    const { email, password } = credentials;

    const user = await this.userRepository.findOne({ where: { email }, relations: ['role'], });
    const role = await this.roleRepository.findOne({ where: { id: user.role.id }, relations: [ 'permissions' ], });
    
    if (!user) {
      throw new UnauthorizedException("Wrong email");
    }

    if (user.isValidated === false) {
      throw new BadRequestException("Your account is not validated");
    }

    if (!await bcrypt.compare(password, user.password)) {
      throw new UnauthorizedException("Wrong password!");
    }
    console.log('debut');
    
    const payload = { 
      username: user.name, 
      sub: user.id,
      email: email,
      role: user.role,
      permission: role.permissions
    };

    const access_token = this.jwtService.sign(payload);

    console.log('fin', access_token); 
    return {access_token, user: user}
    

  }//✅

  async updateUserProfile(profilDto: ProfileDto): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id: profilDto.id } });
    if (!user) { throw new HttpException('user not found', HttpStatus.NOT_FOUND); }

    if (profilDto.emailU) { user.email = profilDto.emailU; }
    if (profilDto.name) { user.name = profilDto.name; }
    if (profilDto.password) { user.password = profilDto.password }

    await this.userRepository.save(user);
    return user;
  }//✅

  async generateUserToken(id) {
    const accessToken = this.jwtService.sign({ id }, { expiresIn: '24h' });
    const refreshToken = uuidv4();
    const user = this.userRepository.findOne({ where: { id } });

    return {
      accessToken,
      refreshToken
    }
  }//✅

  async refresh(refreshStr: string): Promise<string | undefined> {
    const refreshToken = await this.retieveRefreshToken(refreshStr);
    if (!refreshToken) {
      return undefined;
    }
    const accessToken = {
      userId: refreshToken.userId,
    }

    return sign(accessToken, process.env.JWT_SECRET, { expiresIn: '24h' });
  }//✅

  private retieveRefreshToken(
    refreshStr: string
  ): Promise<RefreshToken | undefined> {
    try {
      const decoded = jwt.verify(refreshStr, process.env.REFRESH_SECRET);
      if (typeof decoded === 'string') {
        return undefined
      }
      return Promise.resolve(
        this.refreshTokens.find((token: RefreshToken) => token.id === decoded.id),
      )
    } catch (e) {

    }
  }//✅

  async logout(refreshStr): Promise<void> {
    const refreshToken = await this.retieveRefreshToken(refreshStr);

    if (!refreshToken) {
      return;
    }
    this.refreshTokens = this.refreshTokens.filter(
      (refreshToken: RefreshToken) => refreshToken.id !== refreshToken.id,
    )
  }//✅

  async getUserInfo(token: string): Promise<any> {
    try {
      const decoded = this.jwtService.verify(token);
      if (!decoded) {
        throw new UnauthorizedException('Token invalide.');
      }
      const userInfo = await this.getUserDetails(decoded.id);
      return userInfo;
    } catch (error) {
      throw new UnauthorizedException('Token invalide ou expiré.');
    }
  }//✅

  async getUserDetails(id: number): Promise<any> {
    try {
      // const id = parseInt(id);
      const user = await this.userRepository.findOne({ where: { id } });
      if (!user) {
        throw new UnauthorizedException("No user with this id");
      }
      return user;
    } catch (error) {
      throw new UnauthorizedException("User infos get error.");
    }
  }//✅

  async sendValidationEmail(token: string, name: string, email: string) {
    const validationLink = `http://localhost:3000/auth/verify/${token}`;
    const encodedLink = validationLink;

    const mailOptions = {
      to: email,
      subject: 'Validate your account by click on the link',
      html: `<html>
                <head>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            margin: 20px;
                            padding: 28px 0px;
                            background-color: #f6f6f6;
                        }
                        .main-container {
                          margin: 20px;
                          padding: 28px 0px;
                          background-color: #f6f6f6;
                        }
                        .email-container {
                            width: 80%;
                            max-width: 600px;
                            margin: 0 auto;
                            padding: 20px;
                            background-color: #ffffff;
                            box-shadow: 0px 0px 10px 10px rgba(113, 6, 6, 0.1);
                            border-radius: 15px;
                        }
                        .email-header {
                            text-align: center;
                            padding-bottom: 20px;
                        }
                        .email-header h2{
                            color: #3498db;
                        }
                        .email-body {
                            font-size: 16px;
                            line-height: 1.5;
                            color: #333333;
                        }
                        .email-footer {
                            padding-top: 15px;
                            color: #888888;
                            font-size: 14px;
                        }
                        a[href] {
                            color: #fcfdfe;
                        }
                        
                        .button {
                            display: inline-block;
                            color: #ffffff;
                            background-color: #3498db;
                            padding: 10px 20px;
                            text-decoration: none;
                            border-radius: 15px;
                            cursor: pointer;
                            transition: background-color 0.5s ease;
                        }
                        .button:hover {
                              background-color: #719ff4;
                        }
                    </style>
                </head>
                <body>
                    <div class="main-container">
                      <div class="email-container">
                          <div class="email-header">
                              <h2>Bienvenue sur ${process.env.APP_NAME}!</h2>
                          </div>
                          <div class="email-body"> 
                              <p>Bonjour,</p>
                              <p>Merci de vous être inscrit sur ---. Veuillez cliquer sur le bouton ci-dessous pour valider votre compte :</p>
                              <p style="text-align: center;"><a href="${encodedLink}" class="button">Valider mon compte</a></p>
                              <p>Si vous n'avez pas créé de compte sur ${process.env.APP_NAME}, veuillez ignorer cet email.</p>
                          </div>
                          <div class="email-footer">
                              <p>Cordialement,</p>
                              <p>L'équipe de ${process.env.APP_NAME}</p>
                          </div>
                      </div>
                    </div>
                </body>
              </html>`
    };

    await this.mailerService.sendMail(mailOptions);
  }//✅

  async findByEmail(email: string): Promise<User> {
    return this.userRepository.findOne({ where: { email } });
  }//✅

  async generateResetPasswordToken(user: User): Promise<string> {
    const payload = { userId: user.id };
    const token = await this.jwtService.signAsync(payload, {
      expiresIn: '24h',
    });
    user.resetPasswordToken = token;
    user.resetPasswordTokenExpiration = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes from now
    await this.userRepository.save(user);
    return token;
  }//✅

  async validateResetPasswordToken(token: string): Promise<User | null> {
    const decoded = await this.jwtService.verifyAsync(token);
    if (!decoded) {
      return null;
    }
    const user = await this.userRepository.findOne({
      where: {
        resetPasswordToken: token,
        resetPasswordTokenExpiration: MoreThanOrEqual(new Date())
      },
    });
    if (!user) {
      return null;
    }
    return user;
  }//✅

  async resetPassword(user: User, newPassword: string): Promise<void> {
    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordTokenExpiration = null;
    await this.userRepository.save(user);
  }//✅

  async sendResetPasswordEmail(user: User) {
    const token = await this.generateResetPasswordToken(user);
    const resetUrl = `http://localhost:3000/auth/reset-password?token=${token}`;

    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Reset Password Request',
      html: `
        <h1>Reset your password for ${process.env.APP_NAME}</h1>
        <p>Click on the following link to reset your password:</p>
        <a href="${resetUrl}">Reset Password</a>
        <p>This link will expire in 60 minutes.</p>
      `,
    });
  }//✅

  async sendResetPasswordSuccessEmail(user: User) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Reset Password Request',
      html: `
        <h1>Reset your password for ${process.env.APP_NAME}</h1>
        <p>Your password were changed successfully!</p>
      `,
    });
  }//✅

  async hashPassword(password: string): Promise<string> {
    const saltOrRounds = 10;
    return bcrypt.hash(password, saltOrRounds);
  }//✅

  async updatePassword(id, updatePasswordDto: UpdatePasswordDto) {
    try {
      // Trouver l'utilisateur par son ID
      const utilisateur = await this.userRepository.findOne({ where: { id } });
      if (!utilisateur) {
        throw new Error('Utilisateur introuvable');
      }

      const isPasswordMatch = await bcrypt.compare(updatePasswordDto.oldPassword, utilisateur.password);
      if (!isPasswordMatch) {
        throw new Error("Votre ancien mot de passe est erroné!");
      }

      if (updatePasswordDto.newPassword !== updatePasswordDto.confirmNewPassword) {
        throw new HttpException("Les nouveaux mots de passe ne correspondent pas", HttpStatus.BAD_REQUEST);
      }

      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(updatePasswordDto.newPassword, saltRounds);

      updatePasswordDto.newPassword = hashedPassword;

      utilisateur.password = updatePasswordDto.newPassword;
      await this.userRepository.save(utilisateur);

      return "utilisateur enregistré avec succès";
    } catch (error) {
      throw new Error('Une erreur est survenue lors de la mise à jour du mot de passe');
    }
  }//✅    

  async assignRoleToUser(userId: number, roleId: number): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    const role = await this.roleRepository.findOne({ where: { id: roleId } });

    if (!user || !role) {
      throw new NotFoundException('User or Role not found');
    }

    user.role = role;
    return this.userRepository.save(user);
  }

  async getUserWithPermissions(userId: number): Promise<User> {
    return this.userRepository.createQueryBuilder('user')
      .leftJoinAndSelect('user.role', 'role')
      .leftJoinAndSelect('role.permissions', 'permissions')
      .where('user.id = :id', { id: userId })
      .getOne();
  }
}