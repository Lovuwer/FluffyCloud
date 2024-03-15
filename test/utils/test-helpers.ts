/**
 * Test Utilities and Helpers
 * Provides helper functions for integration tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import jwt from 'jsonwebtoken';

// Mock services for testing without external dependencies
export const mockPrismaService = {
  tenant: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  user: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  role: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  permission: {
    findUnique: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
  },
  userRole: {
    findUnique: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    delete: jest.fn(),
    deleteMany: jest.fn(),
  },
  rolePermission: {
    findMany: jest.fn(),
    create: jest.fn(),
    createMany: jest.fn(),
    deleteMany: jest.fn(),
  },
  oAuthClient: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
  authorizationCode: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  oAuthToken: {
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    updateMany: jest.fn(),
  },
  session: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    deleteMany: jest.fn(),
    count: jest.fn(),
  },
  auditLog: {
    findMany: jest.fn(),
    create: jest.fn(),
    count: jest.fn(),
  },
  task: {
    findUnique: jest.fn(),
    findMany: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  $transaction: jest.fn((callback) => callback(mockPrismaService)),
};

export const mockRedisService = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  exists: jest.fn(),
  setSession: jest.fn(),
  getSession: jest.fn(),
  invalidateSession: jest.fn(),
  invalidateUserSessions: jest.fn(),
};

/**
 * Create a test tenant object
 */
export function createTestTenant(
  overrides: Partial<TestTenant> = {},
): TestTenant {
  return {
    id: 'test-tenant-id',
    name: 'Test Tenant',
    slug: 'test-tenant',
    isActive: true,
    settings: {
      allowSelfRegistration: true,
      requireEmailVerification: false,
      passwordPolicy: {
        minLength: 8,
        requireUppercase: true,
        requireNumber: true,
        requireSpecial: false,
      },
      sessionTimeout: 60,
      mfaRequired: false,
      allowedDomains: [],
    },
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

/**
 * Create a test user object
 */
export function createTestUser(overrides: Partial<TestUser> = {}): TestUser {
  return {
    id: 'test-user-id',
    tenantId: 'test-tenant-id',
    email: 'test@example.com',
    passwordHash:
      '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyNiGZJzFjKzq.', // password: Test123!
    firstName: 'Test',
    lastName: 'User',
    emailVerified: true,
    isActive: true,
    lastLoginAt: null,
    metadata: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

/**
 * Create a test role object
 */
export function createTestRole(overrides: Partial<TestRole> = {}): TestRole {
  return {
    id: 'test-role-id',
    tenantId: 'test-tenant-id',
    name: 'user',
    description: 'Default user role',
    isSystemRole: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

/**
 * Create a test permission object
 */
export function createTestPermission(
  overrides: Partial<TestPermission> = {},
): TestPermission {
  return {
    id: 'test-permission-id',
    name: 'users:read',
    description: 'Read users',
    resource: 'users',
    action: 'read',
    ...overrides,
  };
}

/**
 * Create a test OAuth client object
 */
export function createTestOAuthClient(
  overrides: Partial<TestOAuthClient> = {},
): TestOAuthClient {
  return {
    id: 'test-oauth-client-id',
    tenantId: 'test-tenant-id',
    clientId: 'test_client_id_12345678901234567890',
    clientSecretHash:
      '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyNiGZJzFjKzq.',
    name: 'Test OAuth Client',
    description: 'A test OAuth client',
    redirectUris: ['http://localhost:3000/callback'],
    allowedGrantTypes: ['authorization_code', 'refresh_token'],
    allowedScopes: ['openid', 'profile', 'email'],
    isConfidential: true,
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

/**
 * Generate a mock JWT access token for testing
 */
export function generateTestAccessToken(
  userId: string,
  tenantId: string,
  roles: string[] = ['user'],
  permissions: string[] = ['users:read:own'],
): string {
  const payload = {
    sub: userId,
    email: 'test@example.com',
    tenantId,
    roles,
    permissions,
    type: 'access',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 900, // 15 minutes
    iss: 'iam-platform',
  };

  // Use a test secret for mock tokens
  return jwt.sign(payload, 'test-secret-key-for-testing-only');
}

/**
 * Generate a mock JWT refresh token for testing
 */
export function generateTestRefreshToken(
  userId: string,
  tenantId: string,
): string {
  const payload = {
    sub: userId,
    tenantId,
    type: 'refresh',
    jti: `test-jti-${Date.now()}`,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 604800, // 7 days
    iss: 'iam-platform',
  };

  return jwt.sign(payload, 'test-secret-key-for-testing-only');
}

/**
 * Generate Authorization header value
 */
export function getAuthHeader(token: string): string {
  return `Bearer ${token}`;
}

/**
 * Reset all mock function calls
 */
export function resetMocks(): void {
  jest.clearAllMocks();
}

/**
 * Clean up test data - placeholder for actual implementation
 * In a real integration test setup, this would truncate test database tables
 */
export function cleanupTestData(): void {
  // This would be implemented with actual database cleanup
  // For now, just reset mocks
  resetMocks();
}

// Type definitions for test objects
export interface TenantSettings {
  allowSelfRegistration: boolean;
  requireEmailVerification: boolean;
  passwordPolicy: {
    minLength: number;
    requireUppercase: boolean;
    requireNumber: boolean;
    requireSpecial: boolean;
  };
  sessionTimeout: number;
  mfaRequired: boolean;
  allowedDomains: string[];
}

export interface TestTenant {
  id: string;
  name: string;
  slug: string;
  isActive: boolean;
  settings: TenantSettings;
  createdAt: Date;
  updatedAt: Date;
}

export interface TestUser {
  id: string;
  tenantId: string;
  email: string;
  passwordHash: string | null;
  firstName: string;
  lastName: string;
  emailVerified: boolean;
  isActive: boolean;
  lastLoginAt: Date | null;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface TestRole {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  isSystemRole: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface TestPermission {
  id: string;
  name: string;
  description: string;
  resource: string;
  action: string;
}

export interface TestOAuthClient {
  id: string;
  tenantId: string | null;
  clientId: string;
  clientSecretHash: string;
  name: string;
  description: string | null;
  redirectUris: string[];
  allowedGrantTypes: string[];
  allowedScopes: string[];
  isConfidential: boolean;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Setup a minimal test module with common configuration
 */
export async function createTestModule(
  imports: any[] = [],
  providers: any[] = [],
  controllers: any[] = [],
): Promise<TestingModule> {
  return Test.createTestingModule({
    imports: [
      ConfigModule.forRoot({
        isGlobal: true,
        envFilePath: '.env.test',
      }),
      ...imports,
    ],
    providers,
    controllers,
  }).compile();
}

/**
 * Configure a NestJS app for testing
 */
export function configureTestApp(app: INestApplication): void {
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );
}
