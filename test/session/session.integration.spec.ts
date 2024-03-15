/**
 * Session Management Integration Tests
 * Tests session creation, validation, revocation, and limits
 */

import { Test, TestingModule } from '@nestjs/testing';
import {
  mockPrismaService,
  mockRedisService,
  createTestTenant,
  createTestUser,
  resetMocks,
} from '../utils/test-helpers.js';

import { SessionService } from '../../src/modules/session/session.service.js';
import { PrismaService } from '../../src/database/prisma.service.js';
import { RedisService } from '../../src/modules/redis/redis.service.js';
import { ConfigService } from '@nestjs/config';

describe('Session Management Integration Tests', () => {
  let sessionService: SessionService;

  const testTenant = createTestTenant();
  const testUser = createTestUser();

  beforeEach(async () => {
    resetMocks();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      providers: [
        SessionService,
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

    sessionService = moduleFixture.get<SessionService>(SessionService);
  });

  describe('Session Creation', () => {
    it('should create session on login', async () => {
      mockPrismaService.session.count.mockResolvedValue(0);
      mockPrismaService.session.create.mockResolvedValue({
        id: 'session-id',
        userId: testUser.id,
        tenantId: testTenant.id,
        sessionTokenHash: 'hashed-token',
        ipAddress: '127.0.0.1',
        userAgent:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        deviceInfo: {
          browser: 'Chrome',
          os: 'Windows',
          device: 'desktop',
        },
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 86400000),
      });
      mockRedisService.set.mockResolvedValue('OK');

      const result = await sessionService.createSession({
        userId: testUser.id,
        tenantId: testTenant.id,
        ipAddress: '127.0.0.1',
        userAgent:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      });

      expect(result).toHaveProperty('token');
      expect(result).toHaveProperty('session');
      expect(result.token).toBeDefined();
      expect(result.token.length).toBeGreaterThan(0);
      expect(result.session.userId).toBe(testUser.id);

      // Should store in both database and Redis
      expect(mockPrismaService.session.create).toHaveBeenCalled();
      expect(mockRedisService.set).toHaveBeenCalled();
    });

    it('should parse device info from user agent', async () => {
      mockPrismaService.session.count.mockResolvedValue(0);
      mockPrismaService.session.create.mockImplementation((params: any) => {
        return Promise.resolve({
          id: 'session-id',
          ...params.data,
          createdAt: new Date(),
          lastActiveAt: new Date(),
        });
      });
      mockRedisService.set.mockResolvedValue('OK');

      const result = await sessionService.createSession({
        userId: testUser.id,
        tenantId: testTenant.id,
        ipAddress: '192.168.1.1',
        userAgent:
          'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
      });

      expect(result.session.deviceInfo).toBeDefined();
      // The UA parser should extract device info
      expect(typeof result.session.deviceInfo).toBe('object');
    });
  });

  describe('Session Validation', () => {
    it('should validate session from Redis cache', async () => {
      const sessionData = {
        id: 'session-id',
        userId: testUser.id,
        tenantId: testTenant.id,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0',
        deviceInfo: {},
        createdAt: new Date().toISOString(),
        lastActiveAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      };

      mockRedisService.get.mockResolvedValue(JSON.stringify(sessionData));

      const result = await sessionService.validateSession('valid-token');

      expect(result).not.toBeNull();
      expect(result?.userId).toBe(testUser.id);

      // Should check Redis first
      expect(mockRedisService.get).toHaveBeenCalled();
    });

    it('should fallback to database if not in cache', async () => {
      mockRedisService.get.mockResolvedValue(null); // Not in cache
      mockPrismaService.session.findFirst.mockResolvedValue({
        id: 'session-id',
        userId: testUser.id,
        tenantId: testTenant.id,
        sessionTokenHash: 'token-hash',
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0',
        deviceInfo: {},
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 86400000),
        revokedAt: null,
      });
      mockRedisService.set.mockResolvedValue('OK');

      const result = await sessionService.validateSession('valid-token');

      expect(result).not.toBeNull();
      expect(mockPrismaService.session.findFirst).toHaveBeenCalled();

      // Should re-cache the session
      expect(mockRedisService.set).toHaveBeenCalled();
    });

    it('should return null for expired session', async () => {
      const expiredSessionData = {
        id: 'session-id',
        userId: testUser.id,
        tenantId: testTenant.id,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0',
        deviceInfo: {},
        createdAt: new Date().toISOString(),
        lastActiveAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() - 1000).toISOString(), // Expired
      };

      mockRedisService.get.mockResolvedValue(
        JSON.stringify(expiredSessionData),
      );
      mockRedisService.del.mockResolvedValue(1);

      const result = await sessionService.validateSession('expired-token');

      expect(result).toBeNull();
      expect(mockRedisService.del).toHaveBeenCalled(); // Should clean up expired session
    });

    it('should return null for revoked session', async () => {
      mockRedisService.get.mockResolvedValue(null);
      mockPrismaService.session.findFirst.mockResolvedValue(null); // Query excludes revoked sessions

      const result = await sessionService.validateSession('revoked-token');

      expect(result).toBeNull();
    });
  });

  describe('Session Revocation', () => {
    it('should revoke individual session', async () => {
      mockPrismaService.session.findUnique.mockResolvedValue({
        id: 'session-id',
        userId: testUser.id,
        sessionTokenHash: 'token-hash',
      });
      mockPrismaService.session.update.mockResolvedValue({});
      mockRedisService.del.mockResolvedValue(1);

      await sessionService.revokeSession('session-id', 'logout');

      expect(mockPrismaService.session.update).toHaveBeenCalledWith({
        where: { id: 'session-id' },
        data: expect.objectContaining({
          revokedAt: expect.any(Date),
          revokeReason: 'logout',
        }),
      });
      expect(mockRedisService.del).toHaveBeenCalled();
    });

    it('should revoke all sessions except current', async () => {
      const sessions = [
        { id: 'session-1', sessionTokenHash: 'hash-1' },
        { id: 'session-2', sessionTokenHash: 'hash-2' },
        { id: 'session-3', sessionTokenHash: 'hash-3' }, // Keep this one
      ];

      mockPrismaService.session.findMany.mockResolvedValue(
        sessions.filter((s) => s.id !== 'session-3'),
      );
      mockPrismaService.session.findUnique.mockImplementation((params: any) => {
        const session = sessions.find((s) => s.id === params.where.id);
        return Promise.resolve(session || null);
      });
      mockPrismaService.session.update.mockResolvedValue({});
      mockRedisService.del.mockResolvedValue(1);

      const count = await sessionService.revokeAllUserSessions(
        testUser.id,
        'session-3', // Except this session
        'logout_all',
      );

      expect(count).toBe(2);
      // session-3 should not be revoked
      expect(mockPrismaService.session.update).not.toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'session-3' },
        }),
      );
    });
  });

  describe('Session Limits', () => {
    it('should enforce session limit per user', async () => {
      // Simulate 5 existing sessions (at limit)
      mockPrismaService.session.count.mockResolvedValue(5);
      mockPrismaService.session.findFirst.mockResolvedValue({
        id: 'oldest-session',
        userId: testUser.id,
        sessionTokenHash: 'oldest-hash',
        createdAt: new Date(Date.now() - 1000000),
      });
      mockPrismaService.session.findUnique.mockResolvedValue({
        id: 'oldest-session',
        userId: testUser.id,
        sessionTokenHash: 'oldest-hash',
      });
      mockPrismaService.session.update.mockResolvedValue({});
      mockPrismaService.session.create.mockResolvedValue({
        id: 'new-session',
        userId: testUser.id,
        tenantId: testTenant.id,
        sessionTokenHash: 'new-hash',
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0',
        deviceInfo: {},
        createdAt: new Date(),
        lastActiveAt: new Date(),
        expiresAt: new Date(Date.now() + 86400000),
      });
      mockRedisService.del.mockResolvedValue(1);
      mockRedisService.set.mockResolvedValue('OK');

      const result = await sessionService.createSession({
        userId: testUser.id,
        tenantId: testTenant.id,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0',
      });

      // Should have revoked the oldest session
      expect(mockPrismaService.session.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'oldest-session' },
          data: expect.objectContaining({
            revokedAt: expect.any(Date),
          }),
        }),
      );

      // New session should still be created
      expect(result.session).toBeDefined();
    });
  });

  describe('Session Activity', () => {
    it('should update last_active_at on activity', async () => {
      const oldLastActive = new Date(Date.now() - 10 * 60 * 1000); // 10 minutes ago

      const sessionData = {
        id: 'session-id',
        userId: testUser.id,
        tenantId: testTenant.id,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0',
        deviceInfo: {},
        createdAt: new Date().toISOString(),
        lastActiveAt: oldLastActive.toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      };

      mockRedisService.get.mockResolvedValue(JSON.stringify(sessionData));
      mockPrismaService.session.update.mockResolvedValue({});
      mockRedisService.set.mockResolvedValue('OK');

      await sessionService.validateSession('valid-token');

      // Should update lastActiveAt since it's been more than 5 minutes
      expect(mockPrismaService.session.update).toHaveBeenCalled();
    });

    it('should throttle last_active_at updates', async () => {
      const recentLastActive = new Date(Date.now() - 2 * 60 * 1000); // 2 minutes ago

      const sessionData = {
        id: 'session-id',
        userId: testUser.id,
        tenantId: testTenant.id,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0',
        deviceInfo: {},
        createdAt: new Date().toISOString(),
        lastActiveAt: recentLastActive.toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      };

      mockRedisService.get.mockResolvedValue(JSON.stringify(sessionData));

      await sessionService.validateSession('valid-token');

      // Should NOT update since less than 5 minutes have passed
      expect(mockPrismaService.session.update).not.toHaveBeenCalled();
    });
  });

  describe('Active Sessions', () => {
    it('should list all active sessions for user', async () => {
      mockPrismaService.session.findMany.mockResolvedValue([
        {
          id: 'session-1',
          userId: testUser.id,
          tenantId: testTenant.id,
          ipAddress: '127.0.0.1',
          userAgent: 'Chrome on Windows',
          deviceInfo: { browser: 'Chrome', os: 'Windows' },
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 86400000),
        },
        {
          id: 'session-2',
          userId: testUser.id,
          tenantId: testTenant.id,
          ipAddress: '192.168.1.100',
          userAgent: 'Safari on iPhone',
          deviceInfo: { browser: 'Safari', os: 'iOS' },
          createdAt: new Date(),
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 86400000),
        },
      ]);

      const sessions = await sessionService.getActiveSessions(testUser.id);

      expect(sessions).toHaveLength(2);
      expect(sessions[0].ipAddress).toBe('127.0.0.1');
      expect(sessions[1].ipAddress).toBe('192.168.1.100');
    });
  });

  describe('Session Cleanup', () => {
    it('should cleanup expired sessions', async () => {
      mockPrismaService.session.deleteMany.mockResolvedValue({ count: 10 });

      const count = await sessionService.cleanupExpiredSessions();

      expect(count).toBe(10);
      expect(mockPrismaService.session.deleteMany).toHaveBeenCalledWith({
        where: {
          expiresAt: { lt: expect.any(Date) },
        },
      });
    });
  });

  describe('Session Cookie Config', () => {
    it('should return secure cookie configuration', () => {
      const config = sessionService.getSessionCookieConfig();

      expect(config.httpOnly).toBe(true);
      expect(config.sameSite).toBe('lax');
      expect(config.path).toBe('/');
      expect(config.maxAge).toBe(86400000); // 24 hours in ms
    });
  });
});
