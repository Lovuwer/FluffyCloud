import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { RoleService } from './services/role.service.js';
import { PermissionService } from './services/permission.service.js';
import { PrismaService } from '../../database/prisma.service.js';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard.js';
import { RolesGuard } from '../../common/guards/roles.guard.js';
import { Roles } from '../../common/decorators/roles.decorator.js';
import { Permissions } from '../../common/decorators/permissions.decorator.js';
import { CurrentUser } from '../../common/decorators/current-user.decorator.js';

interface RequestUser {
  userId: string;
  tenantId: string;
  roles: string[];
}

/**
 * RBAC Controller
 * Manages roles and permissions
 */
@Controller('rbac')
@UseGuards(JwtAuthGuard, RolesGuard)
export class RbacController {
  constructor(
    private roleService: RoleService,
    private permissionService: PermissionService,
    private prisma: PrismaService,
  ) {}

  // ============== Role Management ==============

  @Post('roles')
  @Roles('tenant_admin', 'super_admin')
  @HttpCode(HttpStatus.CREATED)
  async createRole(
    @Body()
    dto: { name: string; description?: string; permissionIds?: string[] },
    @CurrentUser() user: RequestUser,
  ) {
    return this.roleService.createRole(user.tenantId, dto);
  }

  @Get('roles')
  @Permissions('roles:read', 'roles:list')
  async listRoles(@CurrentUser() user: RequestUser) {
    return this.roleService.listRoles(user.tenantId);
  }

  @Get('roles/:id')
  @Permissions('roles:read')
  async getRole(@Param('id') id: string) {
    return this.roleService.getRoleById(id);
  }

  @Patch('roles/:id')
  @Roles('tenant_admin', 'super_admin')
  async updateRole(
    @Param('id') id: string,
    @Body() dto: { name?: string; description?: string },
  ) {
    return this.roleService.updateRole(id, dto);
  }

  @Delete('roles/:id')
  @Roles('tenant_admin', 'super_admin')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteRole(@Param('id') id: string) {
    await this.roleService.deleteRole(id);
  }

  @Get('roles/:id/permissions')
  @Permissions('roles:read')
  async getRolePermissions(@Param('id') id: string) {
    return this.roleService.getRolePermissions(id);
  }

  @Patch('roles/:id/permissions')
  @Roles('tenant_admin', 'super_admin')
  async setRolePermissions(
    @Param('id') id: string,
    @Body() dto: { permissionIds: string[] },
  ) {
    return this.roleService.setRolePermissions(id, dto.permissionIds);
  }

  // ============== Role Assignment ==============

  @Post('users/:userId/roles/:roleId')
  @Permissions('roles:assign')
  @HttpCode(HttpStatus.CREATED)
  async assignRole(
    @Param('userId') userId: string,
    @Param('roleId') roleId: string,
    @CurrentUser() user: RequestUser,
  ) {
    await this.roleService.assignRoleToUser(
      userId,
      roleId,
      user.tenantId,
      user.userId,
    );
    return { message: 'Role assigned successfully' };
  }

  @Delete('users/:userId/roles/:roleId')
  @Permissions('roles:assign')
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeRole(
    @Param('userId') userId: string,
    @Param('roleId') roleId: string,
    @CurrentUser() user: RequestUser,
  ) {
    await this.roleService.removeRoleFromUser(userId, roleId, user.tenantId);
  }

  @Get('users/:userId/roles')
  @Permissions('roles:read')
  async getUserRoles(
    @Param('userId') userId: string,
    @CurrentUser() user: RequestUser,
  ) {
    return this.roleService.getUserRoles(userId, user.tenantId);
  }

  @Get('users/:userId/permissions')
  @Permissions('roles:read')
  async getUserPermissions(
    @Param('userId') userId: string,
    @CurrentUser() user: RequestUser,
  ) {
    return this.permissionService.getUserPermissions(userId, user.tenantId);
  }

  // ============== Permission Management ==============

  @Get('permissions')
  @Permissions('roles:read')
  async listPermissions() {
    const permissions = await this.prisma.permission.findMany({
      orderBy: [{ resource: 'asc' }, { action: 'asc' }],
    });

    return permissions.map((p) => ({
      id: p.id,
      name: p.name,
      description: p.description,
      resource: p.resource,
      action: p.action,
    }));
  }

  @Post('permissions')
  @Roles('super_admin')
  @HttpCode(HttpStatus.CREATED)
  async createPermission(
    @Body()
    dto: {
      name: string;
      description: string;
      resource: string;
      action: string;
    },
  ) {
    const permission = await this.prisma.permission.create({
      data: {
        name: dto.name,
        description: dto.description,
        resource: dto.resource,
        action: dto.action,
      },
    });

    console.log(`[AUDIT] Permission created: ${permission.name}`);

    return permission;
  }
}
