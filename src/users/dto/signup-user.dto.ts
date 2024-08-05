import { IsString, IsNotEmpty, MinLength, Matches, IsEmail, isString } from 'class-validator';
// import { Role } from 'src/roles/role.enum';

export class SignUpUserDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password: string;

  // @IsString()
  // @IsNotEmpty()
  // roles: Role[];
}