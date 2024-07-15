import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import { JwtAuthGuard } from "src/auth/jwt-auth.guard";

@Controller('profile')
@UseGuards(JwtAuthGuard) // Ou un autre garde en fonction de votre configuration
export class ProfileController {
  @Get()
  getProfile(@Req() req) {
    return req.user; // Les informations de l'utilisateur sont dans req.user
  }
}
