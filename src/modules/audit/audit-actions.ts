/**
 * Audit Actions Enum
 * Comprehensive list of auditable actions in the system
 */
export enum AuditAction {
  // Auth
  USER_LOGIN = 'user.login',
  USER_LOGOUT = 'user.logout',
  USER_LOGIN_FAILED = 'user.login_failed',
  PASSWORD_CHANGED = 'user.password_changed',
  PASSWORD_RESET_REQUESTED = 'user.password_reset_requested',
  MFA_ENABLED = 'user.mfa_enabled',
  MFA_DISABLED = 'user.mfa_disabled',

  // User management
  USER_CREATED = 'user.created',
  USER_UPDATED = 'user.updated',
  USER_DELETED = 'user.deleted',
  USER_ACTIVATED = 'user.activated',
  USER_DEACTIVATED = 'user.deactivated',

  // Roles
  ROLE_CREATED = 'role.created',
  ROLE_UPDATED = 'role.updated',
  ROLE_DELETED = 'role.deleted',
  ROLE_ASSIGNED = 'role.assigned',
  ROLE_REMOVED = 'role.removed',

  // OAuth
  OAUTH_CLIENT_CREATED = 'oauth_client.created',
  OAUTH_CLIENT_UPDATED = 'oauth_client.updated',
  OAUTH_CLIENT_SECRET_ROTATED = 'oauth_client.secret_rotated',
  OAUTH_TOKEN_ISSUED = 'oauth.token_issued',
  OAUTH_TOKEN_REVOKED = 'oauth.token_revoked',

  // Sessions
  SESSION_CREATED = 'session.created',
  SESSION_REVOKED = 'session.revoked',
  SESSION_REVOKED_ALL = 'session.revoked_all',

  // Tenant
  TENANT_CREATED = 'tenant.created',
  TENANT_UPDATED = 'tenant.updated',
  TENANT_SETTINGS_UPDATED = 'tenant.settings_updated',

  // SAML
  SAML_LOGIN = 'saml.login',
  SAML_IDP_CREATED = 'saml.idp_created',
  SAML_IDP_UPDATED = 'saml.idp_updated',
  SAML_IDP_DELETED = 'saml.idp_deleted',

  // Tasks (Demo)
  TASK_CREATED = 'task.created',
  TASK_UPDATED = 'task.updated',
  TASK_DELETED = 'task.deleted',
  TASK_ASSIGNED = 'task.assigned',
}

export type ActorType = 'user' | 'system' | 'oauth_client' | 'api_key';
export type AuditStatus = 'success' | 'failure' | 'error';
