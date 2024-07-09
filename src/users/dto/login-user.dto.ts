import { IsString, IsNotEmpty, MinLength, Matches, IsEmail } from 'class-validator';

export class LoginUserDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @Matches(/^(^=.*[0-9][A-Z])/)
  password: string;
}