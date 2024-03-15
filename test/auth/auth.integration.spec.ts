/**
 * Auth Flow Integration Tests
 * Tests registration, login, token refresh, and logout flows
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AuthController } from '../../src/modules/auth/auth.controller.js';
import { AuthService } from '../../src/modules/auth/auth.service.js';
import { PrismaService } from '../../src/database/prisma.service.js';
import { PasswordService } from '../../src/modules/auth/services/password.service.js';
import { TokenService } from '../../src/modules/auth/services/token.service.js';
import { RedisService } from '../../src/modules/redis/redis.service.js';
import { ConfigService } from '@nestjs/config';
import {
  mockPrismaService,
  mockRedisService,
  createTestTenant,
  createTestUser,
  createTestRole,
  createTestPermission,
  resetMocks,
} from '../utils/test-helpers.js';

describe('Auth Flow Integration Tests', () => {
  let app: INestApplication<App>;
  let authService: AuthService;

  const testTenant = createTestTenant({ slug: 'system' });
  const testUser = createTestUser();
  const testRole = createTestRole();
  const testPermission = createTestPermission();

  beforeEach(async () => {
    resetMocks();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        AuthService,
        PasswordService,
        {
          provide: TokenService,
          useValue: {
            generateAccessToken: jest.fn().mockReturnValue('mock-access-token'),
            generateRefreshToken: jest
              .fn()
              .mockResolvedValue('mock-refresh-token'),
            verifyRefreshToken: jest
              .fn()
              .mockResolvedValue({ sub: testUser.id, jti: 'mock-jti' }),
            revokeRefreshToken: jest.fn().mockResolvedValue(undefined),
            getAccessTokenExpirySeconds: jest.fn().mockReturnValue(900),
          },
        },
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
          useValue: {
            get: jest.fn((key: string) => {
              const config: Record<string, string> = {
                BCRYPT_COST_FACTOR: '12',
              };
              return config[key];
            }),
          },
        },
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        transform: true,
        forbidNonWhitelisted: true,
      }),
    );

    authService = moduleFixture.get<AuthService>(AuthService);

    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('Registration', () => {
    it('should register a new user successfully', async () => {
      // Setup mocks
      mockPrismaService.tenant.findUnique.mockResolvedValue(testTenant);
      mockPrismaService.user.findUnique.mockResolvedValue(null); // No existing user
      mockPrismaService.role.findFirst.mockResolvedValue(testRole);
      mockPrismaService.$transaction.mockImplementation(
        async (callback: any) => {
          const mockTx = {
            user: {
              create: jest.fn().mockResolvedValue({
                ...testUser,
                id: 'new-user-id',
                email: 'newuser@example.com',
              }),
            },
            userRole: {
              create: jest.fn().mockResolvedValue({}),
            },
          };
          return callback(mockTx);
        },
      );

      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'newuser@example.com',
          password: 'SecurePass123!',
          firstName: 'New',
          lastName: 'User',
        })
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('email', 'newuser@example.com');
      expect(response.body).not.toHaveProperty('passwordHash');
    });

    it('should fail with duplicate email in same tenant', async () => {
      // Setup mocks
      mockPrismaService.tenant.findUnique.mockResolvedValue(testTenant);
      mockPrismaService.user.findUnique.mockResolvedValue(testUser); // Existing user

      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!',
          firstName: 'Test',
          lastName: 'User',
        })
        .expect(409);

      expect(response.body.message).toContain('already registered');
    });

    it('should allow same email in different tenant', async () => {
      const tenant2 = createTestTenant({ id: 'tenant-2', slug: 'tenant2' });

      // First call returns tenant2
      mockPrismaService.tenant.findUnique.mockResolvedValue(tenant2);
      mockPrismaService.user.findUnique.mockResolvedValue(null); // No user in tenant2
      mockPrismaService.role.findFirst.mockResolvedValue(
        createTestRole({ tenantId: tenant2.id }),
      );
      mockPrismaService.$transaction.mockImplementation(
        async (callback: any) => {
          const mockTx = {
            user: {
              create: jest.fn().mockResolvedValue({
                ...testUser,
                id: 'new-user-tenant2',
                tenantId: tenant2.id,
              }),
            },
            userRole: {
              create: jest.fn().mockResolvedValue({}),
            },
          };
          return callback(mockTx);
        },
      );

      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'test@example.com', // Same email as testUser
          password: 'SecurePass123!',
          firstName: 'Test',
          lastName: 'User',
          tenantSlug: 'tenant2',
        })
        .expect(201);

      expect(response.body.tenantId).toBe(tenant2.id);
    });

    it('should fail with weak password', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'weak', // Too short
          firstName: 'Test',
          lastName: 'User',
        })
        .expect(400);

      expect(response.body.message).toBeDefined();
    });

    it('should fail with invalid email', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'invalid-email',
          password: 'SecurePass123!',
          firstName: 'Test',
          lastName: 'User',
        })
        .expect(400);

      expect(response.body.message).toBeDefined();
    });
  });

  describe('Login', () => {
    it('should login with valid credentials', async () => {
      // Create a properly hashed password for comparison
      const passwordService = app.get(PasswordService);
      const hashedPassword =
        await passwordService.hashPassword('SecurePass123!');

      mockPrismaService.tenant.findUnique.mockResolvedValue(testTenant);
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...testUser,
        passwordHash: hashedPassword,
      });
      mockPrismaService.user.update.mockResolvedValue(testUser);
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: {
            name: 'user',
            rolePermissions: [{ permission: testPermission }],
          },
        },
      ]);

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!',
        })
        .expect(200);

      expect(response.body).toHaveProperty('accessToken');
      expect(response.body).toHaveProperty('refreshToken');
      expect(response.body).toHaveProperty('expiresIn');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe('test@example.com');
    });

    it('should fail with wrong password', async () => {
      const passwordService = app.get(PasswordService);
      const hashedPassword = await passwordService.hashPassword(
        'CorrectPassword123!',
      );

      mockPrismaService.tenant.findUnique.mockResolvedValue(testTenant);
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...testUser,
        passwordHash: hashedPassword,
      });

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'WrongPassword123!',
        })
        .expect(401);

      expect(response.body.message).toContain('Invalid credentials');
    });

    it('should fail for inactive user', async () => {
      const passwordService = app.get(PasswordService);
      const hashedPassword =
        await passwordService.hashPassword('SecurePass123!');

      mockPrismaService.tenant.findUnique.mockResolvedValue(testTenant);
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...testUser,
        passwordHash: hashedPassword,
        isActive: false,
      });

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!',
        })
        .expect(401);

      expect(response.body.message).toContain('disabled');
    });

    it('should fail for non-existent user', async () => {
      mockPrismaService.tenant.findUnique.mockResolvedValue(testTenant);
      mockPrismaService.user.findUnique.mockResolvedValue(null);

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'SecurePass123!',
        })
        .expect(401);

      expect(response.body.message).toContain('Invalid credentials');
    });
  });

  describe('Token Refresh', () => {
    it('should refresh access token with valid refresh token', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue(testUser);
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: {
            name: 'user',
            rolePermissions: [{ permission: testPermission }],
          },
        },
      ]);

      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({
          refreshToken: 'valid-refresh-token',
        })
        .expect(200);

      expect(response.body).toHaveProperty('accessToken');
      expect(response.body).toHaveProperty('refreshToken');
      expect(response.body).toHaveProperty('expiresIn');
    });

    it('should fail with invalid refresh token', async () => {
      // Override the token service mock to throw
      const tokenService = app.get(TokenService);
      jest
        .spyOn(tokenService, 'verifyRefreshToken')
        .mockRejectedValue(new Error('Invalid token'));

      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({
          refreshToken: 'invalid-refresh-token',
        })
        .expect(500); // Internal error because of mock rejection

      expect(response.body).toBeDefined();
    });

    it('should fail when user is inactive', async () => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        ...testUser,
        isActive: false,
      });

      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({
          refreshToken: 'valid-refresh-token',
        })
        .expect(401);

      expect(response.body.message).toContain('inactive');
    });
  });

  describe('Logout', () => {
    it('should logout successfully and revoke refresh token', async () => {
      await request(app.getHttpServer())
        .post('/auth/logout')
        .send({
          refreshToken: 'valid-refresh-token',
        })
        .expect(204);
    });

    it('should handle logout with invalid token gracefully', async () => {
      // Override the token service mock to throw
      const tokenService = app.get(TokenService);
      jest
        .spyOn(tokenService, 'verifyRefreshToken')
        .mockRejectedValue(new Error('Invalid token'));

      // Logout should still succeed even if token is invalid
      await request(app.getHttpServer())
        .post('/auth/logout')
        .send({
          refreshToken: 'invalid-refresh-token',
        })
        .expect(204);
    });
  });
});
