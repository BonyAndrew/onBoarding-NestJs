import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSIONS_KEY, ROLES_KEY } from 'src/decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles && !requiredPermissions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new UnauthorizedException('User not found in request');
    }

    const userRole = user.role?.name;
    const userPermissions = user.role?.permissions.map(permission => permission.name);

    const hasRole = () => requiredRoles?.includes(userRole);
    const hasPermission = () => requiredPermissions?.some(permission => userPermissions?.includes(permission));

    if (requiredRoles && !hasRole()) {
      return false;
    }
    if (requiredPermissions && !hasPermission()) {
      return false;
    }

    return true;
  }
}