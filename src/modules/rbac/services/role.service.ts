import {
  Injectable,
  NotFoundException,
  ConflictException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../../../database/prisma.service.js';
import { PermissionService } from './permission.service.js';

interface CreateRoleDto {
  name: string;
  description?: string;
  permissionIds?: string[];
}

interface UpdateRoleDto {
  name?: string;
  description?: string;
}

/**
 * Role Service
 * Manages roles and role assignments
 */
@Injectable()
export class RoleService {
  constructor(
    private prisma: PrismaService,
    private permissionService: PermissionService,
  ) {}

  /**
   * Create a custom role for a tenant
   */
  async createRole(tenantId: string, dto: CreateRoleDto) {
    // Check if role name already exists in tenant
    const existing = await this.prisma.role.findUnique({
      where: {
        tenantId_name: {
          tenantId,
          name: dto.name,
        },
      },
    });

    if (existing) {
      throw new ConflictException(`Role '${dto.name}' already exists`);
    }

    const role = await this.prisma.role.create({
      data: {
        tenantId,
        name: dto.name,
        description: dto.description,
        isSystemRole: false,
      },
    });

    // Add permissions if provided
    if (dto.permissionIds?.length) {
      await this.setRolePermissions(role.id, dto.permissionIds);
    }

    console.log(`[AUDIT] Role created: ${role.name} in tenant ${tenantId}`);

    return this.getRoleById(role.id);
  }

  /**
   * Get role by ID with permissions
   */
  async getRoleById(roleId: string) {
    const role = await this.prisma.role.findUnique({
      where: { id: roleId },
      include: {
        rolePermissions: {
          include: {
            permission: true,
          },
        },
      },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return {
      id: role.id,
      tenantId: role.tenantId,
      name: role.name,
      description: role.description,
      isSystemRole: role.isSystemRole,
      permissions: role.rolePermissions.map((rp) => ({
        id: rp.permission.id,
        name: rp.permission.name,
        description: rp.permission.description,
        resource: rp.permission.resource,
        action: rp.permission.action,
      })),
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
    };
  }

  /**
   * Update role
   */
  async updateRole(roleId: string, dto: UpdateRoleDto) {
    const existing = await this.prisma.role.findUnique({
      where: { id: roleId },
    });

    if (!existing) {
      throw new NotFoundException('Role not found');
    }

    // System roles cannot be modified
    if (existing.isSystemRole) {
      throw new ForbiddenException('System roles cannot be modified');
    }

    // Check for name conflict
    if (dto.name && dto.name !== existing.name) {
      const conflict = await this.prisma.role.findUnique({
        where: {
          tenantId_name: {
            tenantId: existing.tenantId,
            name: dto.name,
          },
        },
      });
      if (conflict) {
        throw new ConflictException(`Role '${dto.name}' already exists`);
      }
    }

    await this.prisma.role.update({
      where: { id: roleId },
      data: {
        name: dto.name,
        description: dto.description,
      },
    });

    console.log(`[AUDIT] Role updated: ${roleId}`);

    return this.getRoleById(roleId);
  }

  /**
   * Delete role (cannot delete system roles)
   */
  async deleteRole(roleId: string) {
    const role = await this.prisma.role.findUnique({
      where: { id: roleId },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    if (role.isSystemRole) {
      throw new ForbiddenException('System roles cannot be deleted');
    }

    await this.prisma.role.delete({
      where: { id: roleId },
    });

    console.log(`[AUDIT] Role deleted: ${role.name} (${roleId})`);

    // Invalidate cache for all users who had this role
    await this.permissionService.invalidateTenantCache(role.tenantId);
  }

  /**
   * List roles for a tenant
   */
  async listRoles(tenantId: string) {
    const roles = await this.prisma.role.findMany({
      where: { tenantId },
      include: {
        rolePermissions: {
          include: {
            permission: true,
          },
        },
        _count: {
          select: { userRoles: true },
        },
      },
      orderBy: { name: 'asc' },
    });

    return roles.map((role) => ({
      id: role.id,
      name: role.name,
      description: role.description,
      isSystemRole: role.isSystemRole,
      permissionCount: role.rolePermissions.length,
      userCount: role._count.userRoles,
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
    }));
  }

  /**
   * Assign role to user
   */
  async assignRoleToUser(
    userId: string,
    roleId: string,
    tenantId: string,
    assignedBy?: string,
  ) {
    // Verify role exists and belongs to tenant
    const role = await this.prisma.role.findUnique({
      where: { id: roleId },
    });

    if (!role || role.tenantId !== tenantId) {
      throw new NotFoundException('Role not found');
    }

    // Check if already assigned
    const existing = await this.prisma.userRole.findUnique({
      where: {
        userId_roleId_tenantId: {
          userId,
          roleId,
          tenantId,
        },
      },
    });

    if (existing) {
      throw new ConflictException('Role already assigned to user');
    }

    await this.prisma.userRole.create({
      data: {
        userId,
        roleId,
        tenantId,
        assignedBy,
      },
    });

    console.log(
      `[AUDIT] Role ${role.name} assigned to user ${userId} by ${assignedBy || 'system'}`,
    );

    // Invalidate permission cache
    await this.permissionService.invalidateCache(userId, tenantId);
  }

  /**
   * Remove role from user
   */
  async removeRoleFromUser(userId: string, roleId: string, tenantId: string) {
    const userRole = await this.prisma.userRole.findUnique({
      where: {
        userId_roleId_tenantId: {
          userId,
          roleId,
          tenantId,
        },
      },
    });

    if (!userRole) {
      throw new NotFoundException('Role assignment not found');
    }

    await this.prisma.userRole.delete({
      where: {
        userId_roleId_tenantId: {
          userId,
          roleId,
          tenantId,
        },
      },
    });

    console.log(`[AUDIT] Role ${roleId} removed from user ${userId}`);

    // Invalidate permission cache
    await this.permissionService.invalidateCache(userId, tenantId);
  }

  /**
   * Get user's roles in a tenant
   */
  async getUserRoles(userId: string, tenantId: string) {
    const userRoles = await this.prisma.userRole.findMany({
      where: { userId, tenantId },
      include: {
        role: {
          include: {
            rolePermissions: {
              include: {
                permission: true,
              },
            },
          },
        },
      },
    });

    return userRoles.map((ur) => ({
      id: ur.role.id,
      name: ur.role.name,
      description: ur.role.description,
      isSystemRole: ur.role.isSystemRole,
      assignedAt: ur.assignedAt,
      permissions: ur.role.rolePermissions.map((rp) => rp.permission.name),
    }));
  }

  /**
   * Get role's permissions
   */
  async getRolePermissions(roleId: string) {
    const role = await this.prisma.role.findUnique({
      where: { id: roleId },
      include: {
        rolePermissions: {
          include: {
            permission: true,
          },
        },
      },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return role.rolePermissions.map((rp) => ({
      id: rp.permission.id,
      name: rp.permission.name,
      description: rp.permission.description,
      resource: rp.permission.resource,
      action: rp.permission.action,
    }));
  }

  /**
   * Set role permissions (replaces all existing)
   */
  async setRolePermissions(roleId: string, permissionIds: string[]) {
    const role = await this.prisma.role.findUnique({
      where: { id: roleId },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    if (role.isSystemRole) {
      throw new ForbiddenException(
        'System role permissions cannot be modified',
      );
    }

    // Delete existing permissions
    await this.prisma.rolePermission.deleteMany({
      where: { roleId },
    });

    // Add new permissions
    if (permissionIds.length > 0) {
      await this.prisma.rolePermission.createMany({
        data: permissionIds.map((permissionId) => ({
          roleId,
          permissionId,
        })),
      });
    }

    console.log(
      `[AUDIT] Role ${roleId} permissions updated: ${permissionIds.length} permissions`,
    );

    // Invalidate cache for all users with this role
    await this.permissionService.invalidateTenantCache(role.tenantId);

    return this.getRolePermissions(roleId);
  }
}
