/**
 * RBAC Integration Tests
 * Tests role assignment, permission checking, and permission guards
 */

import { Test, TestingModule } from '@nestjs/testing';
import {
  mockPrismaService,
  mockRedisService,
  createTestTenant,
  createTestUser,
  createTestRole,
  createTestPermission,
  resetMocks,
} from '../utils/test-helpers.js';

import { PermissionService } from '../../src/modules/rbac/services/permission.service.js';
import { RoleService } from '../../src/modules/rbac/services/role.service.js';
import { PrismaService } from '../../src/database/prisma.service.js';
import { RedisService } from '../../src/modules/redis/redis.service.js';
import { ConfigService } from '@nestjs/config';

describe('RBAC Integration Tests', () => {
  const testTenant = createTestTenant();
  const testUser = createTestUser();
  const testRole = createTestRole();
  const testPermission = createTestPermission();

  // Mock PermissionService for RoleService tests
  const mockPermissionService = {
    invalidateCache: jest.fn().mockResolvedValue(undefined),
    invalidateUserPermissionCache: jest.fn().mockResolvedValue(undefined),
    getUserPermissions: jest.fn().mockResolvedValue([]),
    hasPermission: jest.fn().mockResolvedValue(true),
    hasAnyPermission: jest.fn().mockResolvedValue(true),
    hasAllPermissions: jest.fn().mockResolvedValue(true),
  };

  beforeEach(() => {
    resetMocks();
    // Reset the mock functions
    mockPermissionService.invalidateCache.mockReset();
    mockPermissionService.invalidateCache.mockResolvedValue(undefined);
  });

  describe('Role Assignment', () => {
    let roleService: RoleService;

    beforeEach(async () => {
      const moduleFixture: TestingModule = await Test.createTestingModule({
        providers: [
          RoleService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: RedisService,
            useValue: mockRedisService,
          },
          {
            provide: PermissionService,
            useValue: mockPermissionService,
          },
          {
            provide: ConfigService,
            useValue: { get: jest.fn() },
          },
        ],
      }).compile();

      roleService = moduleFixture.get<RoleService>(RoleService);
    });

    it('should assign role to user', async () => {
      mockPrismaService.role.findUnique.mockResolvedValue(testRole);
      mockPrismaService.userRole.findUnique.mockResolvedValue(null); // No existing assignment
      mockPrismaService.userRole.create.mockResolvedValue({
        userId: testUser.id,
        roleId: testRole.id,
        tenantId: testTenant.id,
        assignedAt: new Date(),
        assignedBy: 'admin-user-id',
      });
      mockRedisService.del.mockResolvedValue(1);

      await roleService.assignRoleToUser(
        testUser.id,
        testRole.id,
        testTenant.id,
        'admin-user-id',
      );

      expect(mockPrismaService.userRole.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: testUser.id,
          roleId: testRole.id,
          tenantId: testTenant.id,
        }),
      });

      // Should invalidate permission cache
      expect(mockPermissionService.invalidateCache).toHaveBeenCalled();
    });

    it('should prevent duplicate role assignment', async () => {
      mockPrismaService.role.findUnique.mockResolvedValue(testRole);
      mockPrismaService.userRole.findUnique.mockResolvedValue({
        userId: testUser.id,
        roleId: testRole.id,
      }); // Already assigned

      await expect(
        roleService.assignRoleToUser(testUser.id, testRole.id, testTenant.id),
      ).rejects.toThrow('already assigned');
    });

    it('should remove role from user', async () => {
      mockPrismaService.userRole.findUnique.mockResolvedValue({
        userId: testUser.id,
        roleId: testRole.id,
        tenantId: testTenant.id,
      });
      mockPrismaService.userRole.deleteMany.mockResolvedValue({ count: 1 });
      mockRedisService.del.mockResolvedValue(1);

      await roleService.removeRoleFromUser(
        testUser.id,
        testRole.id,
        testTenant.id,
      );

      expect(mockPrismaService.userRole.deleteMany).toHaveBeenCalledWith({
        where: expect.objectContaining({
          userId: testUser.id,
          roleId: testRole.id,
        }),
      });

      // Should invalidate permission cache
      expect(mockRedisService.del).toHaveBeenCalled();
    });

    it('should get user roles', async () => {
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: testRole,
          assignedAt: new Date(),
        },
        {
          role: { ...testRole, id: 'role-2', name: 'admin' },
          assignedAt: new Date(),
        },
      ]);

      const roles = await roleService.getUserRoles(testUser.id, testTenant.id);

      expect(roles).toHaveLength(2);
      expect(roles[0].role.name).toBe(testRole.name);
    });
  });

  describe('Permission Checking', () => {
    let permissionService: PermissionService;

    beforeEach(async () => {
      const moduleFixture: TestingModule = await Test.createTestingModule({
        providers: [
          PermissionService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: RedisService,
            useValue: mockRedisService,
          },
          {
            provide: ConfigService,
            useValue: { get: jest.fn() },
          },
        ],
      }).compile();

      permissionService =
        moduleFixture.get<PermissionService>(PermissionService);
    });

    it('should allow action with correct permission', async () => {
      mockRedisService.get.mockResolvedValue(null); // No cache
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: {
            rolePermissions: [
              { permission: { name: 'users:read' } },
              { permission: { name: 'users:write' } },
            ],
          },
        },
      ]);
      mockRedisService.set.mockResolvedValue('OK');

      const hasPermission = await permissionService.hasPermission(
        testUser.id,
        testTenant.id,
        'users:read',
      );

      expect(hasPermission).toBe(true);
    });

    it('should deny action without permission', async () => {
      mockRedisService.get.mockResolvedValue(null);
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: {
            rolePermissions: [{ permission: { name: 'users:read' } }],
          },
        },
      ]);
      mockRedisService.set.mockResolvedValue('OK');

      const hasPermission = await permissionService.hasPermission(
        testUser.id,
        testTenant.id,
        'users:delete', // User doesn't have this
      );

      expect(hasPermission).toBe(false);
    });

    it('should handle scoped permissions (own vs all)', async () => {
      mockRedisService.get.mockResolvedValue(null);
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: {
            rolePermissions: [{ permission: { name: 'users:read:own' } }],
          },
        },
      ]);
      mockRedisService.set.mockResolvedValue('OK');

      // Should have the scoped permission
      const hasOwnPermission = await permissionService.hasPermission(
        testUser.id,
        testTenant.id,
        'users:read:own',
      );
      expect(hasOwnPermission).toBe(true);

      // Should NOT have the broader permission
      const hasAllPermission = await permissionService.hasPermission(
        testUser.id,
        testTenant.id,
        'users:read',
      );
      expect(hasAllPermission).toBe(false);
    });

    it('should combine permissions from multiple roles', async () => {
      mockRedisService.get.mockResolvedValue(null);
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: {
            rolePermissions: [{ permission: { name: 'users:read' } }],
          },
        },
        {
          role: {
            rolePermissions: [
              { permission: { name: 'roles:read' } },
              { permission: { name: 'roles:write' } },
            ],
          },
        },
      ]);
      mockRedisService.set.mockResolvedValue('OK');

      const permissions = await permissionService.getUserPermissions(
        testUser.id,
        testTenant.id,
      );

      expect(permissions).toContain('users:read');
      expect(permissions).toContain('roles:read');
      expect(permissions).toContain('roles:write');
    });

    it('should check hasAnyPermission correctly', async () => {
      mockRedisService.get.mockResolvedValue(null);
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: {
            rolePermissions: [{ permission: { name: 'users:read' } }],
          },
        },
      ]);
      mockRedisService.set.mockResolvedValue('OK');

      const hasAny = await permissionService.hasAnyPermission(
        testUser.id,
        testTenant.id,
        ['users:read', 'users:write', 'users:delete'],
      );

      expect(hasAny).toBe(true);
    });

    it('should check hasAllPermissions correctly', async () => {
      mockRedisService.get.mockResolvedValue(null);
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: {
            rolePermissions: [
              { permission: { name: 'users:read' } },
              { permission: { name: 'users:write' } },
            ],
          },
        },
      ]);
      mockRedisService.set.mockResolvedValue('OK');

      const hasAll = await permissionService.hasAllPermissions(
        testUser.id,
        testTenant.id,
        ['users:read', 'users:write'],
      );
      expect(hasAll).toBe(true);

      const hasAllMissing = await permissionService.hasAllPermissions(
        testUser.id,
        testTenant.id,
        ['users:read', 'users:delete'], // Missing delete
      );
      expect(hasAllMissing).toBe(false);
    });

    it('should use cached permissions', async () => {
      // Cache hit
      mockRedisService.get.mockResolvedValue(
        JSON.stringify(['users:read', 'users:write']),
      );

      const permissions = await permissionService.getUserPermissions(
        testUser.id,
        testTenant.id,
      );

      expect(permissions).toContain('users:read');
      expect(permissions).toContain('users:write');

      // Should not query database when cache exists
      expect(mockPrismaService.userRole.findMany).not.toHaveBeenCalled();
    });
  });

  describe('Role Management', () => {
    let roleService: RoleService;

    beforeEach(async () => {
      const moduleFixture: TestingModule = await Test.createTestingModule({
        providers: [
          RoleService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: RedisService,
            useValue: mockRedisService,
          },
          {
            provide: PermissionService,
            useValue: mockPermissionService,
          },
          {
            provide: ConfigService,
            useValue: { get: jest.fn() },
          },
        ],
      }).compile();

      roleService = moduleFixture.get<RoleService>(RoleService);
    });

    it('should create custom role', async () => {
      mockPrismaService.role.create.mockResolvedValue({
        id: 'new-role-id',
        tenantId: testTenant.id,
        name: 'custom_role',
        description: 'A custom role',
        isSystemRole: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const role = await roleService.createRole(testTenant.id, {
        name: 'custom_role',
        description: 'A custom role',
      });

      expect(role.name).toBe('custom_role');
      expect(role.isSystemRole).toBe(false);
    });

    it('should prevent deletion of system roles', async () => {
      mockPrismaService.role.findUnique.mockResolvedValue({
        ...testRole,
        isSystemRole: true,
      });

      await expect(roleService.deleteRole(testRole.id)).rejects.toThrow(
        'system role',
      );
    });

    it('should delete non-system role', async () => {
      const customRole = { ...testRole, isSystemRole: false };
      mockPrismaService.role.findUnique.mockResolvedValue(customRole);
      mockPrismaService.userRole.findFirst.mockResolvedValue(null); // No users assigned
      mockPrismaService.role.delete.mockResolvedValue(customRole);

      await roleService.deleteRole(customRole.id);

      expect(mockPrismaService.role.delete).toHaveBeenCalledWith({
        where: { id: customRole.id },
      });
    });

    it('should get role permissions', async () => {
      mockPrismaService.rolePermission.findMany.mockResolvedValue([
        { permission: { name: 'users:read', id: 'perm-1' } },
        { permission: { name: 'users:write', id: 'perm-2' } },
      ]);

      const permissions = await roleService.getRolePermissions(testRole.id);

      expect(permissions).toHaveLength(2);
      expect(
        permissions.map(
          (p: { permission: { name: string } }) => p.permission.name,
        ),
      ).toContain('users:read');
    });

    it('should set role permissions', async () => {
      mockPrismaService.role.findUnique.mockResolvedValue({
        ...testRole,
        isSystemRole: false,
      });
      mockPrismaService.rolePermission.deleteMany.mockResolvedValue({
        count: 0,
      });
      mockPrismaService.rolePermission.createMany.mockResolvedValue({
        count: 2,
      });

      await roleService.setRolePermissions(testRole.id, ['perm-1', 'perm-2']);

      expect(mockPrismaService.rolePermission.deleteMany).toHaveBeenCalledWith({
        where: { roleId: testRole.id },
      });
      expect(mockPrismaService.rolePermission.createMany).toHaveBeenCalled();
    });
  });
});
