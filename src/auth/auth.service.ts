import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { MailerService } from '@nestjs-modules/mailer';
import { User } from 'src/users/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { RolesService } from 'src/roles/roles.service';
import { Role } from 'src/roles/entities/role.entity';

@Injectable()
export class AuthService {
    constructor(
        private jwtService: JwtService,
        private usersService: UsersService,
        private mailerService: MailerService,
        private roleService: RolesService,
        @InjectRepository(User)
    private userRepository: Repository<User>,
    ) { }
    async validateUser(email, password): Promise<User> {
        const user = await this.userRepository.findOne({where: {email}});

        if (user && await bcrypt.compare(password, user.password)) {
            return user;
        }
        return null;
    } //✅

    async getUserById(id): Promise<User> {
        // const id1 = parseInt(id);
        return this.usersService.findOne(id);
    } //✅

    async userHasPermission(userId: number, permissionName: string): Promise<boolean> {
        const user = await this.usersService.getUserWithPermissions(userId);
        return user.role.permissions.some(permission => permission.name === permissionName);
    }
}
