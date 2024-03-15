import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service.js';
import { PasswordService } from '../auth/services/password.service.js';
import {
  CreateTenantDto,
  UpdateTenantDto,
  TenantSettings,
  UpdateTenantSettingsDto,
} from './dto/index.js';
import { DEFAULT_ROLES } from '../rbac/permissions.js';

const DEFAULT_TENANT_SETTINGS: TenantSettings = {
  allowSelfRegistration: true,
  requireEmailVerification: true,
  passwordPolicy: {
    minLength: 8,
    requireUppercase: true,
    requireNumber: true,
    requireSpecial: false,
  },
  sessionTimeout: 60, // 1 hour
  mfaRequired: false,
  allowedDomains: [],
};

/**
 * Tenant Service
 * Manages tenant lifecycle and settings
 */
@Injectable()
export class TenantService {
  constructor(
    private prisma: PrismaService,
    private passwordService: PasswordService,
  ) {}

  /**
   * Create a new tenant with optional initial admin user
   */
  async createTenant(dto: CreateTenantDto) {
    // Check if slug already exists
    const existing = await this.prisma.tenant.findUnique({
      where: { slug: dto.slug },
    });

    if (existing) {
      throw new ConflictException(`Tenant slug '${dto.slug}' already exists`);
    }

    // Create tenant with transaction
    const tenant = await this.prisma.$transaction(async (tx) => {
      // Create tenant
      const newTenant = await tx.tenant.create({
        data: {
          name: dto.name,
          slug: dto.slug,
          settings: DEFAULT_TENANT_SETTINGS as object,
          isActive: true,
        },
      });

      // Create default roles for tenant
      const roleMap = new Map<string, string>();

      for (const [_key, roleData] of Object.entries(DEFAULT_ROLES)) {
        const role = await tx.role.create({
          data: {
            tenantId: newTenant.id,
            name: roleData.name,
            description: roleData.description,
            isSystemRole: roleData.isSystemRole,
          },
        });
        roleMap.set(roleData.name, role.id);

        // Get or create permissions and assign to role
        for (const permName of roleData.permissions) {
          let permission = await tx.permission.findUnique({
            where: { name: permName },
          });

          if (!permission) {
            const [resource, action] = permName.split(':');
            permission = await tx.permission.create({
              data: {
                name: permName,
                description: `${action} permission for ${resource}`,
                resource,
                action,
              },
            });
          }

          await tx.rolePermission.create({
            data: {
              roleId: role.id,
              permissionId: permission.id,
            },
          });
        }
      }

      // Create initial admin user if email provided
      if (dto.adminEmail) {
        const passwordHash = dto.adminPassword
          ? await this.passwordService.hashPassword(dto.adminPassword)
          : null;

        const adminUser = await tx.user.create({
          data: {
            tenantId: newTenant.id,
            email: dto.adminEmail,
            passwordHash,
            firstName: dto.adminFirstName || 'Admin',
            lastName: dto.adminLastName || 'User',
            emailVerified: true,
            isActive: true,
          },
        });

        // Assign tenant_admin role
        const tenantAdminRoleId = roleMap.get('tenant_admin');
        if (tenantAdminRoleId) {
          await tx.userRole.create({
            data: {
              userId: adminUser.id,
              roleId: tenantAdminRoleId,
              tenantId: newTenant.id,
            },
          });
        }

        // TODO: Send welcome email to admin
        console.log(`[TODO] Send welcome email to ${dto.adminEmail}`);
      }

      return newTenant;
    });

    console.log(`[AUDIT] Tenant created: ${tenant.name} (${tenant.slug})`);

    return {
      id: tenant.id,
      name: tenant.name,
      slug: tenant.slug,
      isActive: tenant.isActive,
      createdAt: tenant.createdAt,
    };
  }

  /**
   * Get tenant by ID
   */
  async getTenant(id: string) {
    const tenant = await this.prisma.tenant.findUnique({
      where: { id },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    return {
      id: tenant.id,
      name: tenant.name,
      slug: tenant.slug,
      isActive: tenant.isActive,
      createdAt: tenant.createdAt,
      updatedAt: tenant.updatedAt,
    };
  }

  /**
   * Get tenant by slug
   */
  async getTenantBySlug(slug: string) {
    const tenant = await this.prisma.tenant.findUnique({
      where: { slug },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    return {
      id: tenant.id,
      name: tenant.name,
      slug: tenant.slug,
      isActive: tenant.isActive,
      createdAt: tenant.createdAt,
      updatedAt: tenant.updatedAt,
    };
  }

  /**
   * List all tenants
   */
  async listTenants() {
    const tenants = await this.prisma.tenant.findMany({
      orderBy: { createdAt: 'desc' },
      include: {
        _count: {
          select: { users: true },
        },
      },
    });

    return tenants.map((t) => ({
      id: t.id,
      name: t.name,
      slug: t.slug,
      isActive: t.isActive,
      userCount: t._count.users,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    }));
  }

  /**
   * Update tenant
   */
  async updateTenant(id: string, dto: UpdateTenantDto) {
    const existing = await this.prisma.tenant.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException('Tenant not found');
    }

    const tenant = await this.prisma.tenant.update({
      where: { id },
      data: {
        name: dto.name,
        isActive: dto.isActive,
      },
    });

    console.log(`[AUDIT] Tenant updated: ${tenant.id}`);

    return {
      id: tenant.id,
      name: tenant.name,
      slug: tenant.slug,
      isActive: tenant.isActive,
      createdAt: tenant.createdAt,
      updatedAt: tenant.updatedAt,
    };
  }

  /**
   * Deactivate tenant (soft delete)
   */
  async deactivateTenant(id: string) {
    const existing = await this.prisma.tenant.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException('Tenant not found');
    }

    await this.prisma.tenant.update({
      where: { id },
      data: { isActive: false },
    });

    console.log(`[AUDIT] Tenant deactivated: ${id}`);
  }

  /**
   * Get tenant settings
   */
  async getTenantSettings(id: string): Promise<TenantSettings> {
    const tenant = await this.prisma.tenant.findUnique({
      where: { id },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    // Merge with defaults in case some settings are missing
    const settings = tenant.settings as TenantSettings | null;
    return {
      ...DEFAULT_TENANT_SETTINGS,
      ...settings,
    };
  }

  /**
   * Update tenant settings
   */
  async updateTenantSettings(
    id: string,
    dto: UpdateTenantSettingsDto,
  ): Promise<TenantSettings> {
    const tenant = await this.prisma.tenant.findUnique({
      where: { id },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    const currentSettings =
      (tenant.settings as TenantSettings | null) || DEFAULT_TENANT_SETTINGS;

    const updatedSettings: TenantSettings = {
      ...currentSettings,
      ...dto,
      passwordPolicy: {
        ...currentSettings.passwordPolicy,
        ...dto.passwordPolicy,
      },
      brandingConfig: dto.brandingConfig
        ? { ...currentSettings.brandingConfig, ...dto.brandingConfig }
        : currentSettings.brandingConfig,
    };

    await this.prisma.tenant.update({
      where: { id },
      data: { settings: updatedSettings as object },
    });

    console.log(`[AUDIT] Tenant settings updated: ${id}`);

    return updatedSettings;
  }
}
