import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../database/prisma.service.js';
import { RedisService } from '../../redis/redis.service.js';
import { permissionImplies, PERMISSION_INHERITANCE } from '../permissions.js';

const PERMISSION_CACHE_TTL = 300; // 5 minutes

/**
 * Permission Service
 * Handles permission checking with caching
 */
@Injectable()
export class PermissionService {
  constructor(
    private prisma: PrismaService,
    private redis: RedisService,
  ) {}

  /**
   * Get cache key for user permissions
   */
  private getCacheKey(userId: string, tenantId: string): string {
    return `permissions:${userId}:${tenantId}`;
  }

  /**
   * Get all permissions for a user in a tenant
   */
  async getUserPermissions(
    userId: string,
    tenantId: string,
  ): Promise<string[]> {
    // Check cache first
    const cacheKey = this.getCacheKey(userId, tenantId);
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // Get from database
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

    // Collect all permissions from all roles
    const permissionSet = new Set<string>();
    for (const userRole of userRoles) {
      for (const rp of userRole.role.rolePermissions) {
        permissionSet.add(rp.permission.name);
      }
    }

    const permissions = Array.from(permissionSet);

    // Cache for 5 minutes
    await this.redis.set(
      cacheKey,
      JSON.stringify(permissions),
      PERMISSION_CACHE_TTL,
    );

    return permissions;
  }

  /**
   * Check if user has a specific permission
   */
  async hasPermission(
    userId: string,
    tenantId: string,
    permission: string,
  ): Promise<boolean> {
    const permissions = await this.getUserPermissions(userId, tenantId);

    // Check direct permission
    if (permissions.includes(permission)) {
      return true;
    }

    // Check if any held permission implies the requested one
    for (const held of permissions) {
      if (permissionImplies(held, permission)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if user has any of the specified permissions
   */
  async hasAnyPermission(
    userId: string,
    tenantId: string,
    permissions: string[],
  ): Promise<boolean> {
    for (const permission of permissions) {
      if (await this.hasPermission(userId, tenantId, permission)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check if user has all of the specified permissions
   */
  async hasAllPermissions(
    userId: string,
    tenantId: string,
    permissions: string[],
  ): Promise<boolean> {
    for (const permission of permissions) {
      if (!(await this.hasPermission(userId, tenantId, permission))) {
        return false;
      }
    }
    return true;
  }

  /**
   * Get effective permissions from multiple roles
   * Includes inherited permissions
   */
  getEffectivePermissions(permissions: string[]): string[] {
    const effectiveSet = new Set<string>(permissions);

    // Add inherited permissions
    for (const permission of permissions) {
      const inherited = PERMISSION_INHERITANCE[permission];
      if (inherited) {
        for (const p of inherited) {
          effectiveSet.add(p);
        }
      }
    }

    return Array.from(effectiveSet);
  }

  /**
   * Invalidate permission cache for a user
   */
  async invalidateCache(userId: string, tenantId: string): Promise<void> {
    const cacheKey = this.getCacheKey(userId, tenantId);
    await this.redis.del(cacheKey);
    console.log(`[CACHE] Permission cache invalidated for user ${userId}`);
  }

  /**
   * Invalidate permission cache for all users in a tenant
   * (Used when role permissions change)
   */
  async invalidateTenantCache(tenantId: string): Promise<void> {
    // Get all users in tenant
    const users = await this.prisma.user.findMany({
      where: { tenantId },
      select: { id: true },
    });

    for (const user of users) {
      await this.invalidateCache(user.id, tenantId);
    }
  }
}
