/**
 * RBAC Permission Definitions
 * Fine-grained permission system with resource:action:scope format
 */

// Resource types
export type Resource =
  | 'users'
  | 'roles'
  | 'tenants'
  | 'clients'
  | 'audit_logs'
  | 'settings';

// Action types
export type Action =
  | 'create'
  | 'read'
  | 'update'
  | 'delete'
  | 'list'
  | 'manage'
  | 'assign';

// Scope types
export type Scope = 'own' | 'tenant' | 'all';

// Permission format: resource:action or resource:action:scope
export interface Permission {
  resource: Resource;
  action: Action;
  scope?: Scope;
}

// All available permissions
export const PERMISSIONS = {
  // User permissions
  USERS_CREATE: 'users:create',
  USERS_READ: 'users:read',
  USERS_READ_OWN: 'users:read:own',
  USERS_UPDATE: 'users:update',
  USERS_UPDATE_OWN: 'users:update:own',
  USERS_DELETE: 'users:delete',
  USERS_LIST: 'users:list',
  USERS_MANAGE: 'users:manage',

  // Role permissions
  ROLES_CREATE: 'roles:create',
  ROLES_READ: 'roles:read',
  ROLES_UPDATE: 'roles:update',
  ROLES_DELETE: 'roles:delete',
  ROLES_LIST: 'roles:list',
  ROLES_ASSIGN: 'roles:assign',
  ROLES_MANAGE: 'roles:manage',

  // Tenant permissions
  TENANTS_READ: 'tenants:read',
  TENANTS_UPDATE: 'tenants:update',
  TENANTS_MANAGE: 'tenants:manage',
  TENANTS_CREATE: 'tenants:create',
  TENANTS_DELETE: 'tenants:delete',
  TENANTS_LIST: 'tenants:list',

  // OAuth Client permissions
  CLIENTS_CREATE: 'clients:create',
  CLIENTS_READ: 'clients:read',
  CLIENTS_UPDATE: 'clients:update',
  CLIENTS_DELETE: 'clients:delete',
  CLIENTS_LIST: 'clients:list',
  CLIENTS_MANAGE: 'clients:manage',

  // Audit log permissions
  AUDIT_LOGS_READ: 'audit_logs:read',
  AUDIT_LOGS_LIST: 'audit_logs:list',

  // Settings permissions
  SETTINGS_READ: 'settings:read',
  SETTINGS_UPDATE: 'settings:update',
} as const;

// Permission inheritance map
// If a user has 'users:manage', they implicitly have all users:* permissions
export const PERMISSION_INHERITANCE: Record<string, string[]> = {
  'users:manage': [
    PERMISSIONS.USERS_CREATE,
    PERMISSIONS.USERS_READ,
    PERMISSIONS.USERS_READ_OWN,
    PERMISSIONS.USERS_UPDATE,
    PERMISSIONS.USERS_UPDATE_OWN,
    PERMISSIONS.USERS_DELETE,
    PERMISSIONS.USERS_LIST,
  ],
  'roles:manage': [
    PERMISSIONS.ROLES_CREATE,
    PERMISSIONS.ROLES_READ,
    PERMISSIONS.ROLES_UPDATE,
    PERMISSIONS.ROLES_DELETE,
    PERMISSIONS.ROLES_LIST,
    PERMISSIONS.ROLES_ASSIGN,
  ],
  'tenants:manage': [
    PERMISSIONS.TENANTS_READ,
    PERMISSIONS.TENANTS_UPDATE,
    PERMISSIONS.TENANTS_CREATE,
    PERMISSIONS.TENANTS_DELETE,
    PERMISSIONS.TENANTS_LIST,
  ],
  'clients:manage': [
    PERMISSIONS.CLIENTS_CREATE,
    PERMISSIONS.CLIENTS_READ,
    PERMISSIONS.CLIENTS_UPDATE,
    PERMISSIONS.CLIENTS_DELETE,
    PERMISSIONS.CLIENTS_LIST,
  ],
};

// Default role definitions
export const DEFAULT_ROLES = {
  SUPER_ADMIN: {
    name: 'super_admin',
    description: 'Super administrator with all permissions (platform level)',
    isSystemRole: true,
    permissions: Object.values(PERMISSIONS),
  },
  TENANT_ADMIN: {
    name: 'tenant_admin',
    description: 'Tenant administrator',
    isSystemRole: true,
    permissions: [
      PERMISSIONS.USERS_CREATE,
      PERMISSIONS.USERS_READ,
      PERMISSIONS.USERS_UPDATE,
      PERMISSIONS.USERS_DELETE,
      PERMISSIONS.USERS_LIST,
      PERMISSIONS.ROLES_READ,
      PERMISSIONS.ROLES_LIST,
      PERMISSIONS.ROLES_ASSIGN,
      PERMISSIONS.CLIENTS_CREATE,
      PERMISSIONS.CLIENTS_READ,
      PERMISSIONS.CLIENTS_UPDATE,
      PERMISSIONS.CLIENTS_DELETE,
      PERMISSIONS.CLIENTS_LIST,
      PERMISSIONS.SETTINGS_READ,
      PERMISSIONS.SETTINGS_UPDATE,
      PERMISSIONS.AUDIT_LOGS_READ,
      PERMISSIONS.AUDIT_LOGS_LIST,
    ],
  },
  USER_MANAGER: {
    name: 'user_manager',
    description: 'User manager with user CRUD and role assignment',
    isSystemRole: true,
    permissions: [
      PERMISSIONS.USERS_CREATE,
      PERMISSIONS.USERS_READ,
      PERMISSIONS.USERS_UPDATE,
      PERMISSIONS.USERS_DELETE,
      PERMISSIONS.USERS_LIST,
      PERMISSIONS.ROLES_READ,
      PERMISSIONS.ROLES_LIST,
      PERMISSIONS.ROLES_ASSIGN,
    ],
  },
  USER: {
    name: 'user',
    description: 'Regular user',
    isSystemRole: true,
    permissions: [
      PERMISSIONS.USERS_READ_OWN,
      PERMISSIONS.USERS_UPDATE_OWN,
      PERMISSIONS.SETTINGS_READ,
    ],
  },
};

/**
 * Parse permission string into components
 */
export function parsePermission(permission: string): Permission | null {
  const parts = permission.split(':');
  if (parts.length < 2 || parts.length > 3) {
    return null;
  }

  return {
    resource: parts[0] as Resource,
    action: parts[1] as Action,
    scope: parts[2] as Scope | undefined,
  };
}

/**
 * Check if permission A implies permission B
 * e.g., 'users:read' implies 'users:read:own'
 */
export function permissionImplies(
  permissionA: string,
  permissionB: string,
): boolean {
  if (permissionA === permissionB) {
    return true;
  }

  // Check inheritance
  const inherited = PERMISSION_INHERITANCE[permissionA];
  if (inherited?.includes(permissionB)) {
    return true;
  }

  // Check scope inheritance
  // 'users:read' implies 'users:read:own' and 'users:read:tenant'
  const parsedA = parsePermission(permissionA);
  const parsedB = parsePermission(permissionB);

  if (!parsedA || !parsedB) {
    return false;
  }

  if (
    parsedA.resource === parsedB.resource &&
    parsedA.action === parsedB.action
  ) {
    // If A has no scope, it implies all scopes
    if (!parsedA.scope && parsedB.scope) {
      return true;
    }
    // 'all' scope implies 'tenant' and 'own'
    if (parsedA.scope === 'all') {
      return true;
    }
    // 'tenant' scope implies 'own'
    if (parsedA.scope === 'tenant' && parsedB.scope === 'own') {
      return true;
    }
  }

  return false;
}
