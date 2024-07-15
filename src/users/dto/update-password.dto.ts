import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class UpdatePasswordDto {
    id: number;

    @IsString()
    @MinLength(8)
    oldPassword: string;

    @IsString()
    @MinLength(8)
    newPassword: string;

    @IsString()
    @MinLength(8)
    confirmNewPassword: string;
}
