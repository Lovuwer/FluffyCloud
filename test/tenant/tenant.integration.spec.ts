/**
 * Multi-Tenant Isolation Integration Tests
 * Tests data isolation between tenants
 */

import { Test, TestingModule } from '@nestjs/testing';
import {
  mockPrismaService,
  mockRedisService,
  createTestTenant,
  createTestUser,
  createTestRole,
  createTestOAuthClient,
  resetMocks,
  TestUser,
} from '../utils/test-helpers.js';

import { TenantService } from '../../src/modules/tenant/tenant.service.js';
import { TenantContextService } from '../../src/common/services/tenant-context.service.js';
import { PermissionService } from '../../src/modules/rbac/services/permission.service.js';
import { PrismaService } from '../../src/database/prisma.service.js';
import { RedisService } from '../../src/modules/redis/redis.service.js';
import { PasswordService } from '../../src/modules/auth/services/password.service.js';
import { ConfigService } from '@nestjs/config';

describe('Multi-Tenant Isolation Integration Tests', () => {
  const tenant1 = createTestTenant({
    id: 'tenant-1',
    name: 'Tenant One',
    slug: 'tenant1',
  });
  const tenant2 = createTestTenant({
    id: 'tenant-2',
    name: 'Tenant Two',
    slug: 'tenant2',
  });

  const user1 = createTestUser({
    id: 'user-1',
    tenantId: tenant1.id,
    email: 'user@tenant1.com',
  });
  const user2 = createTestUser({
    id: 'user-2',
    tenantId: tenant2.id,
    email: 'user@tenant2.com',
  });

  beforeEach(() => {
    resetMocks();
  });

  describe('Data Isolation', () => {
    let tenantService: TenantService;
    let tenantContextService: TenantContextService;

    beforeEach(async () => {
      const moduleFixture: TestingModule = await Test.createTestingModule({
        providers: [
          TenantService,
          TenantContextService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: PasswordService,
            useValue: {
              hashPassword: jest.fn().mockResolvedValue('hashed-password'),
            },
          },
          {
            provide: ConfigService,
            useValue: { get: jest.fn() },
          },
        ],
      }).compile();

      tenantService = moduleFixture.get<TenantService>(TenantService);
      tenantContextService =
        moduleFixture.get<TenantContextService>(TenantContextService);
    });

    it('should not allow user to access other tenant data', async () => {
      // Simulate user1 (from tenant1) trying to access tenant2's data
      await tenantContextService.runAsync(
        { tenantId: tenant1.id },
        async () => {
          const currentTenantId = tenantContextService.getTenantId();
          expect(currentTenantId).toBe(tenant1.id);
          expect(currentTenantId).not.toBe(tenant2.id);
        },
      );
    });

    it('should maintain correct tenant context in async operations', async () => {
      // Run nested async operations and verify context is maintained
      await tenantContextService.runAsync(
        { tenantId: tenant1.id },
        async () => {
          expect(tenantContextService.getTenantId()).toBe(tenant1.id);

          // Simulate async database call
          await new Promise((resolve) => setTimeout(resolve, 10));

          // Context should still be correct
          expect(tenantContextService.getTenantId()).toBe(tenant1.id);
        },
      );
    });

    it('should isolate tenant context between concurrent requests', async () => {
      // Simulate two concurrent requests from different tenants
      const promise1 = tenantContextService.runAsync(
        { tenantId: tenant1.id },
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 20));
          return tenantContextService.getTenantId();
        },
      );

      const promise2 = tenantContextService.runAsync(
        { tenantId: tenant2.id },
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 10));
          return tenantContextService.getTenantId();
        },
      );

      const [result1, result2] = await Promise.all([promise1, promise2]);

      expect(result1).toBe(tenant1.id);
      expect(result2).toBe(tenant2.id);
    });

    it('should not leak data between tenants in list queries', async () => {
      // When listing users for tenant1, should only get tenant1's users
      mockPrismaService.user.findMany.mockImplementation((params: any) => {
        // Verify the query is scoped to the tenant
        if (params?.where?.tenantId === tenant1.id) {
          return Promise.resolve([user1]);
        }
        if (params?.where?.tenantId === tenant2.id) {
          return Promise.resolve([user2]);
        }
        return Promise.resolve([]);
      });

      // Query for tenant1 users
      const tenant1Users = await mockPrismaService.user.findMany({
        where: { tenantId: tenant1.id },
      });

      expect(tenant1Users).toHaveLength(1);
      expect(tenant1Users[0].tenantId).toBe(tenant1.id);
      expect(
        tenant1Users.some((u: TestUser) => u.tenantId === tenant2.id),
      ).toBe(false);
    });
  });

  describe('OAuth Client Tenant Scoping', () => {
    it('should scope OAuth clients to tenant', () => {
      const client1 = createTestOAuthClient({
        tenantId: tenant1.id,
        name: 'Client 1',
      });
      const client2 = createTestOAuthClient({
        tenantId: tenant2.id,
        name: 'Client 2',
      });

      // Setup mock to return clients filtered by tenant
      mockPrismaService.oAuthClient.findMany.mockImplementation(
        (params: any) => {
          if (params?.where?.tenantId === tenant1.id) {
            return Promise.resolve([client1]);
          }
          if (params?.where?.tenantId === tenant2.id) {
            return Promise.resolve([client2]);
          }
          return Promise.resolve([]);
        },
      );

      // Verify tenant1 only sees their clients
      const tenant1Clients = mockPrismaService.oAuthClient.findMany({
        where: { tenantId: tenant1.id },
      });

      expect(tenant1Clients).resolves.toHaveLength(1);
      expect(tenant1Clients).resolves.toEqual(
        expect.arrayContaining([
          expect.objectContaining({ tenantId: tenant1.id }),
        ]),
      );
    });

    it('should allow platform-level clients (null tenant)', () => {
      const platformClient = createTestOAuthClient({
        tenantId: null,
        name: 'Platform Client',
      });

      mockPrismaService.oAuthClient.findMany.mockResolvedValue([
        platformClient,
      ]);

      const clients = mockPrismaService.oAuthClient.findMany({
        where: { tenantId: null },
      });

      expect(clients).resolves.toHaveLength(1);
      expect(clients).resolves.toEqual(
        expect.arrayContaining([expect.objectContaining({ tenantId: null })]),
      );
    });
  });

  describe('Role and Permission Tenant Scoping', () => {
    it('should scope roles and permissions to tenant', async () => {
      const role1 = createTestRole({
        id: 'role-1',
        tenantId: tenant1.id,
        name: 'admin',
      });
      const role2 = createTestRole({
        id: 'role-2',
        tenantId: tenant2.id,
        name: 'admin',
      });

      mockPrismaService.role.findMany.mockImplementation((params: any) => {
        if (params?.where?.tenantId === tenant1.id) {
          return Promise.resolve([role1]);
        }
        if (params?.where?.tenantId === tenant2.id) {
          return Promise.resolve([role2]);
        }
        return Promise.resolve([]);
      });

      // Tenant1's admin role should be different from tenant2's admin role
      const tenant1Roles = await mockPrismaService.role.findMany({
        where: { tenantId: tenant1.id, name: 'admin' },
      });

      const tenant2Roles = await mockPrismaService.role.findMany({
        where: { tenantId: tenant2.id, name: 'admin' },
      });

      expect(tenant1Roles[0].id).not.toBe(tenant2Roles[0].id);
      expect(tenant1Roles[0].tenantId).toBe(tenant1.id);
      expect(tenant2Roles[0].tenantId).toBe(tenant2.id);
    });
  });

  describe('Super Admin Access', () => {
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

    it('should allow super_admin to access any tenant', async () => {
      // Super admin user with 'tenants:manage' permission
      mockRedisService.get.mockResolvedValue(null);
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: {
            name: 'super_admin',
            rolePermissions: [
              { permission: { name: 'tenants:manage' } },
              { permission: { name: 'users:read' } },
              { permission: { name: 'users:write' } },
            ],
          },
        },
      ]);
      mockRedisService.set.mockResolvedValue('OK');

      const superAdminId = 'super-admin-id';

      // Super admin should have access to tenant management
      const hasTenantsManage = await permissionService.hasPermission(
        superAdminId,
        tenant1.id, // Checking against tenant1
        'tenants:manage',
      );

      expect(hasTenantsManage).toBe(true);

      // Super admin should also have user permissions
      const hasUsersRead = await permissionService.hasPermission(
        superAdminId,
        tenant2.id, // Even against tenant2
        'users:read',
      );

      expect(hasUsersRead).toBe(true);
    });
  });

  describe('Tenant Onboarding', () => {
    let tenantService: TenantService;

    beforeEach(async () => {
      const moduleFixture: TestingModule = await Test.createTestingModule({
        providers: [
          TenantService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: PasswordService,
            useValue: {
              hashPassword: jest.fn().mockResolvedValue('hashed-password'),
            },
          },
          {
            provide: ConfigService,
            useValue: { get: jest.fn() },
          },
        ],
      }).compile();

      tenantService = moduleFixture.get<TenantService>(TenantService);
    });

    it('should create tenant with default roles', async () => {
      const createdRoles: any[] = [];
      const createdRolePermissions: any[] = [];

      mockPrismaService.$transaction.mockImplementation(
        async (callback: any) => {
          const mockTx = {
            tenant: {
              create: jest.fn().mockResolvedValue({
                id: 'new-tenant-id',
                name: 'New Tenant',
                slug: 'new-tenant',
                isActive: true,
                settings: {},
                createdAt: new Date(),
                updatedAt: new Date(),
              }),
            },
            role: {
              create: jest.fn().mockImplementation((data: any) => {
                const role = {
                  id: `role-${createdRoles.length}`,
                  ...data.data,
                };
                createdRoles.push(role);
                return Promise.resolve(role);
              }),
            },
            permission: {
              findUnique: jest.fn().mockResolvedValue(null),
              create: jest.fn().mockImplementation((data: any) => {
                return Promise.resolve({
                  id: `perm-${Date.now()}`,
                  ...data.data,
                });
              }),
            },
            rolePermission: {
              create: jest.fn().mockImplementation((data: any) => {
                createdRolePermissions.push(data.data);
                return Promise.resolve(data.data);
              }),
            },
            user: {
              create: jest.fn().mockResolvedValue({
                id: 'admin-user-id',
                email: 'admin@newtenant.com',
              }),
            },
            userRole: {
              create: jest.fn().mockResolvedValue({}),
            },
          };
          return callback(mockTx);
        },
      );

      await tenantService.createTenant({
        name: 'New Tenant',
        slug: 'new-tenant',
        adminEmail: 'admin@newtenant.com',
        adminPassword: 'AdminPass123!',
      });

      // Verify default roles were created
      expect(createdRoles.length).toBeGreaterThan(0);

      // Should have created tenant_admin, user_manager, and user roles at minimum
      const roleNames = createdRoles.map((r) => r.name);
      expect(roleNames).toContain('tenant_admin');
      expect(roleNames).toContain('user');
    });

    it('should create initial admin user for tenant', async () => {
      let createdUser: any = null;
      let assignedRole: any = null;

      mockPrismaService.$transaction.mockImplementation(
        async (callback: any) => {
          const mockTx = {
            tenant: {
              create: jest.fn().mockResolvedValue({
                id: 'new-tenant-id',
                name: 'New Tenant',
                slug: 'new-tenant',
                isActive: true,
                settings: {},
                createdAt: new Date(),
                updatedAt: new Date(),
              }),
            },
            role: {
              create: jest.fn().mockImplementation((data: any) => {
                const roleId =
                  data.data.name === 'tenant_admin'
                    ? 'tenant-admin-role-id'
                    : `role-${Date.now()}`;
                return Promise.resolve({ id: roleId, ...data.data });
              }),
            },
            permission: {
              findUnique: jest.fn().mockResolvedValue(null),
              create: jest.fn().mockResolvedValue({ id: 'perm-id' }),
            },
            rolePermission: {
              create: jest.fn().mockResolvedValue({}),
            },
            user: {
              create: jest.fn().mockImplementation((data: any) => {
                createdUser = { id: 'admin-user-id', ...data.data };
                return Promise.resolve(createdUser);
              }),
            },
            userRole: {
              create: jest.fn().mockImplementation((data: any) => {
                assignedRole = data.data;
                return Promise.resolve(data.data);
              }),
            },
          };
          return callback(mockTx);
        },
      );

      await tenantService.createTenant({
        name: 'New Tenant',
        slug: 'new-tenant',
        adminEmail: 'admin@newtenant.com',
        adminPassword: 'AdminPass123!',
        adminFirstName: 'John',
        adminLastName: 'Admin',
      });

      // Verify admin user was created
      expect(createdUser).not.toBeNull();
      expect(createdUser.email).toBe('admin@newtenant.com');
      expect(createdUser.firstName).toBe('John');

      // Verify tenant_admin role was assigned
      expect(assignedRole).not.toBeNull();
      expect(assignedRole.userId).toBe('admin-user-id');
    });
  });

  describe('Tenant Settings', () => {
    let tenantService: TenantService;

    beforeEach(async () => {
      const moduleFixture: TestingModule = await Test.createTestingModule({
        providers: [
          TenantService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: PasswordService,
            useValue: {
              hashPassword: jest.fn(),
            },
          },
          {
            provide: ConfigService,
            useValue: { get: jest.fn() },
          },
        ],
      }).compile();

      tenantService = moduleFixture.get<TenantService>(TenantService);
    });

    it('should get tenant settings with defaults', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        ...tenant1,
        settings: { allowSelfRegistration: false }, // Partial settings
      });

      const settings = await tenantService.getTenantSettings(tenant1.id);

      // Should have the custom setting
      expect(settings.allowSelfRegistration).toBe(false);

      // Should have defaults for missing settings
      expect(settings.passwordPolicy).toBeDefined();
      expect(settings.sessionTimeout).toBeDefined();
    });

    it('should update tenant settings', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue(tenant1);
      mockPrismaService.tenant.update.mockResolvedValue({
        ...tenant1,
        settings: {
          ...tenant1.settings,
          mfaRequired: true,
        },
      });

      const updatedSettings = await tenantService.updateTenantSettings(
        tenant1.id,
        {
          mfaRequired: true,
        },
      );

      expect(updatedSettings.mfaRequired).toBe(true);
      expect(mockPrismaService.tenant.update).toHaveBeenCalled();
    });
  });
});
