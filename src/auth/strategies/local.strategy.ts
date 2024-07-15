import { Strategy } from "passport-local";
import { PassportStrategy } from "@nestjs/passport";
import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { UsersService } from "src/users/users.service";
import { LoginUserDto } from "src/users/dto/login-user.dto";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    constructor(
        @Inject('Auth_Service') private readonly userService: UsersService,
    ) {
        super();
    }

    async validate(credentials: LoginUserDto) {
        const { email, password } = credentials;
        console.log('inside the local strategy');
        console.log(email);
        console.log(password);
        const user = await this.userService.login(credentials);
        if(!user){
            throw new UnauthorizedException();
        }
        return user;
    }
}