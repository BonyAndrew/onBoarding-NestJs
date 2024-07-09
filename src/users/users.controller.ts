import { Controller, Get, Headers, Post, Body, Patch, Param, Delete, UseGuards, Req, UnauthorizedException } from '@nestjs/common';
import { UsersService } from './users.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Post()
  create(@Body() createUserDto: User) { 
    console.log("createUserDto", createUserDto);
    return this.usersService.createUser(createUserDto);
  }

  @Get()
  findAll() {
    return this.usersService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id) {
    return this.usersService.findOne(id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(+id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id: number) {
    return this.usersService.remove(id);
  }

 

  // @Get('/me')
  // async me(@Headers('authorization') token: string): Promise<any> {
  //   if (!token) {
  //     throw new UnauthorizedException('No token found.');
  //   }
  //   const cleanedToken = token.startsWith('Bearer ') ? token.slice(7) : token;
  //   return this.usersService.getUserInfo(cleanedToken);
  // }

  
  // me(@Req() req, user: User) {
  //   const use = user.id;
  //   return this.usersService.findOne(use);
  // }
}