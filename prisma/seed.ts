import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // Create default "system" tenant
  const systemTenant = await prisma.tenant.upsert({
    where: { slug: 'system' },
    update: {},
    create: {
      name: 'System',
      slug: 'system',
      settings: {},
      isActive: true,
    },
  });
  console.log(`✅ Created system tenant: ${systemTenant.id}`);

  // Create basic permissions
  const permissionsData = [
    { name: 'users:read', description: 'Read user data', resource: 'users', action: 'read' },
    { name: 'users:write', description: 'Create and update users', resource: 'users', action: 'write' },
    { name: 'users:delete', description: 'Delete users', resource: 'users', action: 'delete' },
    { name: 'roles:read', description: 'Read role data', resource: 'roles', action: 'read' },
    { name: 'roles:write', description: 'Create and update roles', resource: 'roles', action: 'write' },
    { name: 'tenants:read', description: 'Read tenant data', resource: 'tenants', action: 'read' },
    { name: 'tenants:write', description: 'Create and update tenants', resource: 'tenants', action: 'write' },
    { name: 'audit_logs:read', description: 'Read audit logs', resource: 'audit_logs', action: 'read' },
    { name: 'audit_logs:list', description: 'List audit logs', resource: 'audit_logs', action: 'list' },
    // Demo task permissions
    { name: 'tasks:create', description: 'Create tasks', resource: 'tasks', action: 'create' },
    { name: 'tasks:read', description: 'Read tasks', resource: 'tasks', action: 'read' },
    { name: 'tasks:update', description: 'Update any task', resource: 'tasks', action: 'update' },
    { name: 'tasks:update:own', description: 'Update own tasks', resource: 'tasks', action: 'update:own' },
    { name: 'tasks:delete', description: 'Delete tasks', resource: 'tasks', action: 'delete' },
    { name: 'tasks:list', description: 'List tasks', resource: 'tasks', action: 'list' },
    { name: 'tasks:assign', description: 'Assign tasks to users', resource: 'tasks', action: 'assign' },
  ];

  const permissions = await Promise.all(
    permissionsData.map((p) =>
      prisma.permission.upsert({
        where: { name: p.name },
        update: {},
        create: p,
      }),
    ),
  );
  console.log(`✅ Created ${permissions.length} permissions`);

  // Create system roles for the system tenant
  const rolesData = [
    {
      name: 'super_admin',
      description: 'Super administrator with all permissions',
      isSystemRole: true,
    },
    {
      name: 'tenant_admin',
      description: 'Tenant administrator',
      isSystemRole: true,
    },
    {
      name: 'user',
      description: 'Regular user',
      isSystemRole: true,
    },
    // Demo roles
    {
      name: 'task_admin',
      description: 'Task administrator with all task permissions',
      isSystemRole: false,
    },
    {
      name: 'team_member',
      description: 'Team member who can create and manage own tasks',
      isSystemRole: false,
    },
    {
      name: 'viewer',
      description: 'Read-only access to tasks',
      isSystemRole: false,
    },
  ];

  for (const roleData of rolesData) {
    const role = await prisma.role.upsert({
      where: {
        tenantId_name: {
          tenantId: systemTenant.id,
          name: roleData.name,
        },
      },
      update: {},
      create: {
        ...roleData,
        tenantId: systemTenant.id,
      },
    });

    // Assign permissions based on role
    let permissionNames: string[] = [];
    if (roleData.name === 'super_admin') {
      permissionNames = permissions.map((p) => p.name);
    } else if (roleData.name === 'tenant_admin') {
      permissionNames = ['users:read', 'users:write', 'users:delete', 'roles:read', 'roles:write', 'audit_logs:read', 'audit_logs:list'];
    } else if (roleData.name === 'user') {
      permissionNames = ['users:read'];
    } else if (roleData.name === 'task_admin') {
      permissionNames = ['tasks:create', 'tasks:read', 'tasks:update', 'tasks:delete', 'tasks:list', 'tasks:assign'];
    } else if (roleData.name === 'team_member') {
      permissionNames = ['tasks:create', 'tasks:read', 'tasks:update:own', 'tasks:list'];
    } else if (roleData.name === 'viewer') {
      permissionNames = ['tasks:read', 'tasks:list'];
    }

    // Create role-permission associations
    for (const permName of permissionNames) {
      const perm = permissions.find((p) => p.name === permName);
      if (perm) {
        await prisma.rolePermission.upsert({
          where: {
            roleId_permissionId: {
              roleId: role.id,
              permissionId: perm.id,
            },
          },
          update: {},
          create: {
            roleId: role.id,
            permissionId: perm.id,
          },
        });
      }
    }

    console.log(`✅ Created role: ${role.name} with ${permissionNames.length} permissions`);
  }

  // Create OAuth scopes
  const scopesData = [
    { name: 'openid', description: 'OpenID Connect scope', isDefault: true },
    { name: 'profile', description: 'Access to user profile information', isDefault: true },
    { name: 'email', description: 'Access to user email', isDefault: true },
    { name: 'offline_access', description: 'Request refresh tokens', isDefault: false },
    { name: 'users:read', description: 'Read user data', isDefault: false },
    { name: 'users:write', description: 'Write user data', isDefault: false },
  ];

  for (const scopeData of scopesData) {
    await prisma.oAuthScope.upsert({
      where: { name: scopeData.name },
      update: {},
      create: scopeData,
    });
  }
  console.log(`✅ Created ${scopesData.length} OAuth scopes`);

  console.log('🎉 Database seed completed!');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
