import { IsString, IsNotEmpty, MinLength, Matches, IsEmail } from 'class-validator';

export class SignUpUserDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @Matches(/[0-9][A-Z]/)
  password: string;
}