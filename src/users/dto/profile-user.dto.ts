import { IsEmail, IsNotEmpty, IsNumber, IsOptional, IsString, MinLength } from 'class-validator';

export class ProfileDto {
    @IsOptional()
    @IsNumber()
    id: number;

    @IsOptional()
    @IsString()
    name: string;

    @IsOptional()
    @IsEmail()
    emailU: string;

    @IsOptional()
    @MinLength(8)
    @IsString()
    password: string
}