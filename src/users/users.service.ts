import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { EntityManager, FindOneOptions, FindOptionsWhere, MoreThanOrEqual } from 'typeorm';
import { User } from './entities/user.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import { UpdateUserDto } from './dto/update-user.dto';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import jwt, { sign } from 'jsonwebtoken';
import RefreshToken from 'src/auth/entities/refresh-token.entity';
import { v4 as uuidv4 } from 'uuid';
import { MailerService } from '@nestjs-modules/mailer';


@Injectable()
export class UsersService {

  private refreshTokens: RefreshToken[] = [];

  constructor(
    private readonly entityManager: EntityManager,
    private jwtService: JwtService,
    private readonly mailerService: MailerService
  ) { }

  async getAll() {
    return getRepositoryToken(User);
  }

  async findAllUsers(): Promise<User[]> {
    return await this.entityManager.find(User);
  }

  async findAll(): Promise<User[]> {
    return await this.entityManager.find(User);
  }

  async findOne(id): Promise<User> {
    const options: FindOneOptions<User> = {
      where: {
        id: id,
      } as FindOptionsWhere<User>,
    };
    if (!options) {
      console.log('aucun trouvé');
      throw new NotFoundException();
    }
    return await this.entityManager.findOne(User, options);
  }

  async findOneBy(filter): Promise<User> {
    const options: FindOneOptions<User> = {
      where: filter as FindOptionsWhere<User>,
    };
    if (!options) {
      console.log('aucun trouvé');
      throw new NotFoundException();
    }
    return await this.entityManager.findOne(User, options);
  }

  async create(user): Promise<User> {
    return await this.entityManager.create(user);
  }

  async createUser(user: User): Promise<User> {
    const userN = new User();
    userN.name = user.name;
    userN.email = user.email;
    userN.password = user.password;
    userN.token = user.token;
    return await this.entityManager.save(userN);
  }

  async update(id: number, updateUserDto: UpdateUserDto) {
    const userU = await this.findOne(id);
    if (!userU) {
      throw new NotFoundException();
    }

    Object.assign(userU, updateUserDto);

    return await this.entityManager.save(userU);
  }

  async remove(id: number) {
    const user = await this.findOne(id);
    if (!user) {
      throw new NotFoundException();
    }

    return await this.entityManager.remove(user);
  }

  async register(id, name: string, email: string, password: string) {

    const nameInUse = await this.entityManager.findOne(User, { where: { name } });

    if (nameInUse) {
      throw new BadRequestException('This name is already used');
    }

    const user = new User();
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const token = this.jwtService.sign({ name, email }, { expiresIn: '1h' });

    user.name = name;
    user.email = email;
    user.password = hashedPassword;
    user.token = token;

    console.log('user', name, 'is registered successfully');
    return this.entityManager.save(user);
  }

  async login(
    credentials: LoginUserDto,
    // values: { userAgent: string, ipAddress: string }
  )
  // : Promise<{ access_token: string }> 
  {
    const { name, password } = credentials;

    const user = await this.entityManager.findOne(User, { where: { name } })
    // if (!user) {
    //   throw new UnauthorizedException("This user does not exists!, Check your username!");
    // }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid || !user) {
      throw new UnauthorizedException("Wrong username or password!");
    }

    // return this.newRefreshToken(user, values)
    const payload = { id: user.id };
    // const access_token = this.jwtService.sign(payload, { expiresIn: '1h' });
    console.log('User', user.name, 'connected');
    // return { access_token };
    // return this.generateUserToken(user.id);
    // return { message: "User connected!" }
  }

  async generateUserToken(id) {
    const accessToken = this.jwtService.sign({ id }, { expiresIn: '1h' });
    const refreshToken = uuidv4();
    const user = this.entityManager.findOne(User, { where: { id } });

    return {
      accessToken,
      refreshToken
    }
  }

  async refresh(refreshStr: string): Promise<string | undefined> {
    const refreshToken = await this.retieveRefreshToken(refreshStr);
    if (!refreshToken) {
      return undefined;
    }
    const accessToken = {
      userId: refreshToken.userId,
    }

    return sign(accessToken, process.env.JWT_SECRET, { expiresIn: '1h' });
  }

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
  }

  async logout(refreshStr): Promise<void> {
    const refreshToken = await this.retieveRefreshToken(refreshStr);

    if (!refreshToken) {
      return;
    }
    this.refreshTokens = this.refreshTokens.filter(
      (refreshToken: RefreshToken) => refreshToken.id !== refreshToken.id,
    )
  }

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
  }

  async getUserDetails(id: number): Promise<any> {
    try {
      // const id = parseInt(id);
      const user = await this.entityManager.findOne(User, { where: { id } });
      if (!user) {
        throw new UnauthorizedException("No user with this id");
      }
      return user;
    } catch (error) {
      throw new UnauthorizedException("User infos get error.");
    }
  }

  async sendValidationEmail(token: string, name: string, email: string) {
    const validationLink = `http://localhost:3000/auth/verify/${token}`;
    const encodedLink = validationLink;

    const mailOptions = {
      to: email,
      subject: 'Validate your account by click on the link',
      text: `Hello ${name}, please click on this link to validate your account: ${encodedLink}`,
    };

    await this.mailerService.sendMail(mailOptions);
  }

  async updatePassword(userId: string, newPassword: string): Promise<void> {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.entityManager.createQueryBuilder()
      .update(User)
      .set({ password: hashedPassword })
      .where("id = :id", { id: userId })
      .execute();
  }


  async findByEmail(email: string): Promise<User> {
    return this.entityManager.findOne(User, { where: { email } });
  }

  async generateResetPasswordToken(user: User): Promise<string> {
    const payload = { userId: user.id };
    const token = await this.jwtService.signAsync(payload, {
      expiresIn: '1h',
    });
    user.resetPasswordToken = token;
    user.resetPasswordTokenExpiration = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes from now
    await this.entityManager.save(user);
    return token;
  }

  async validateResetPasswordToken(token: string): Promise<User | null> {
    const decoded = await this.jwtService.verifyAsync(token);
    if (!decoded) {
      return null;
    }
    const user = await this.entityManager.findOne(User,{
      where: {
        resetPasswordToken: token,
        resetPasswordTokenExpiration: MoreThanOrEqual(new Date())
      },
    });
    if (!user) {
      return null;
    }
    return user;
  }

  async resetPassword(user: User, newPassword: string): Promise<void> {
    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordTokenExpiration = null;
    await this.entityManager.save(user);
  }

  async sendResetPasswordEmail(user: User) {
    const token = await this.generateResetPasswordToken(user);
    const resetUrl = `http://localhost:3000/reset-password?token=${token}`;

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
  }

  async sendResetPasswordSuccessEmail(user: User) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Reset Password Request',
      html: `
        <h1>Reset your password for ${process.env.APP_NAME}</h1>
        <p>Your password were changed successfully!:</p>
      `,
    });
  }

}
