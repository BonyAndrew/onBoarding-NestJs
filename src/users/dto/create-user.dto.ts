import { IsString, IsNotEmpty, Matches, MinLength, IsEmail } from 'class-validator';

export class CreateUserDto {

    @IsString()
    @IsNotEmpty()
    name: string;

    @IsString()
    @IsEmail()
    @IsNotEmpty()
    email: string;

    // @IsString()
    // address: string;

    // @IsString()
    // role: string;

    @IsString()
    @IsNotEmpty()
    // @MinLength(8)
    // @Matches(/[0-9][A-Z]/)
    password: string;
}

