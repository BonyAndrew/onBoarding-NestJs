import { IsString, IsNotEmpty, MinLength, Matches, IsEmail } from 'class-validator';

export class LoginUserDto {
  
  id: string;

  @IsString()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password: string;
}