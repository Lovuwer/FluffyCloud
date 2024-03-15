import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import crypto from 'crypto';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const UAParser = require('ua-parser-js');

export interface SessionData {
  id: string;
  userId: string;
  tenantId: string;
  ipAddress: string;
  userAgent: string;
  deviceInfo: object;
  createdAt: Date;
  lastActiveAt: Date;
  expiresAt: Date;
}

interface CreateSessionParams {
  userId: string;
  tenantId: string;
  ipAddress: string;
  userAgent: string;
}

const SESSION_PREFIX = 'session:';
const USER_SESSIONS_PREFIX = 'user_sessions:';
const DEFAULT_SESSION_TTL = 86400; // 24 hours
const MAX_SESSIONS_PER_USER = 5;

/**
 * Session Service
 * Manages user sessions with security features
 */
@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);

  constructor(
    private prisma: PrismaService,
    private redis: RedisService,
  ) {}

  /**
   * Generate secure session token (32 bytes, base64url encoded)
   */
  private generateSessionToken(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  /**
   * Hash session token before storing
   */
  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Parse user agent to get device info
   */
  private parseUserAgent(userAgent: string): object {
    const parser = new UAParser(userAgent);
    const result = parser.getResult();
    return {
      browser: result.browser.name,
      browserVersion: result.browser.version,
      os: result.os.name,
      osVersion: result.os.version,
      device: result.device.type || 'desktop',
      deviceModel: result.device.model,
      deviceVendor: result.device.vendor,
    };
  }

  /**
   * Create a new session
   * Returns plain token (only time it's available!)
   */
  async createSession(
    params: CreateSessionParams,
  ): Promise<{ token: string; session: SessionData }> {
    const { userId, tenantId, ipAddress, userAgent } = params;

    // Check session limit per user
    const existingSessions = await this.prisma.session.count({
      where: {
        userId,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
    });

    if (existingSessions >= MAX_SESSIONS_PER_USER) {
      // Revoke oldest session
      const oldestSession = await this.prisma.session.findFirst({
        where: {
          userId,
          revokedAt: null,
          expiresAt: { gt: new Date() },
        },
        orderBy: { createdAt: 'asc' },
      });

      if (oldestSession) {
        await this.revokeSession(oldestSession.id, 'session_limit');
      }
    }

    // Generate token and hash
    const token = this.generateSessionToken();
    const tokenHash = this.hashToken(token);
    const deviceInfo = this.parseUserAgent(userAgent);

    const expiresAt = new Date(Date.now() + DEFAULT_SESSION_TTL * 1000);

    // Create session in database
    const session = await this.prisma.session.create({
      data: {
        userId,
        tenantId,
        sessionTokenHash: tokenHash,
        ipAddress,
        userAgent,
        deviceInfo,
        expiresAt,
      },
    });

    // Cache in Redis
    const sessionData: SessionData = {
      id: session.id,
      userId,
      tenantId,
      ipAddress,
      userAgent,
      deviceInfo,
      createdAt: session.createdAt,
      lastActiveAt: session.lastActiveAt,
      expiresAt,
    };

    await this.redis.set(
      `${SESSION_PREFIX}${tokenHash}`,
      JSON.stringify(sessionData),
      DEFAULT_SESSION_TTL,
    );

    // Add to user's session set
    await this.redis.set(
      `${USER_SESSIONS_PREFIX}${userId}:${session.id}`,
      tokenHash,
      DEFAULT_SESSION_TTL,
    );

    this.logger.log(
      `Session created for user ${userId}, session ${session.id}`,
    );

    return { token, session: sessionData };
  }

  /**
   * Validate session token
   */
  async validateSession(token: string): Promise<SessionData | null> {
    const tokenHash = this.hashToken(token);

    // Check Redis first
    const cached = await this.redis.get(`${SESSION_PREFIX}${tokenHash}`);
    if (cached) {
      const sessionData = JSON.parse(cached) as SessionData;

      // Check if expired
      if (new Date(sessionData.expiresAt) < new Date()) {
        await this.redis.del(`${SESSION_PREFIX}${tokenHash}`);
        return null;
      }

      // Update last_active_at (throttled - every 5 minutes)
      const lastActive = new Date(sessionData.lastActiveAt);
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      if (lastActive < fiveMinutesAgo) {
        await this.updateLastActive(sessionData.id, tokenHash);
      }

      return sessionData;
    }

    // Check database if not in cache
    const session = await this.prisma.session.findFirst({
      where: {
        sessionTokenHash: tokenHash,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
    });

    if (!session) {
      return null;
    }

    // Re-cache
    const sessionData: SessionData = {
      id: session.id,
      userId: session.userId,
      tenantId: session.tenantId,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      deviceInfo: session.deviceInfo as object,
      createdAt: session.createdAt,
      lastActiveAt: session.lastActiveAt,
      expiresAt: session.expiresAt,
    };

    const ttl = Math.floor((session.expiresAt.getTime() - Date.now()) / 1000);
    if (ttl > 0) {
      await this.redis.set(
        `${SESSION_PREFIX}${tokenHash}`,
        JSON.stringify(sessionData),
        ttl,
      );
    }

    return sessionData;
  }

  /**
   * Update last active timestamp (throttled)
   */
  private async updateLastActive(
    sessionId: string,
    tokenHash: string,
  ): Promise<void> {
    const now = new Date();

    await this.prisma.session.update({
      where: { id: sessionId },
      data: { lastActiveAt: now },
    });

    // Update cache
    const cached = await this.redis.get(`${SESSION_PREFIX}${tokenHash}`);
    if (cached) {
      const sessionData = JSON.parse(cached) as SessionData;
      sessionData.lastActiveAt = now;
      const ttl = Math.floor(
        (new Date(sessionData.expiresAt).getTime() - Date.now()) / 1000,
      );
      if (ttl > 0) {
        await this.redis.set(
          `${SESSION_PREFIX}${tokenHash}`,
          JSON.stringify(sessionData),
          ttl,
        );
      }
    }
  }

  /**
   * Revoke a specific session
   */
  async revokeSession(sessionId: string, reason?: string): Promise<void> {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
    });

    if (!session) {
      return;
    }

    // Mark as revoked in database
    await this.prisma.session.update({
      where: { id: sessionId },
      data: {
        revokedAt: new Date(),
        revokeReason: reason || 'manual',
      },
    });

    // Remove from Redis
    await this.redis.del(`${SESSION_PREFIX}${session.sessionTokenHash}`);
    await this.redis.del(
      `${USER_SESSIONS_PREFIX}${session.userId}:${sessionId}`,
    );

    this.logger.log(`Session ${sessionId} revoked: ${reason || 'manual'}`);
  }

  /**
   * Revoke all sessions for a user
   */
  async revokeAllUserSessions(
    userId: string,
    exceptSessionId?: string,
    reason?: string,
  ): Promise<number> {
    const sessions = await this.prisma.session.findMany({
      where: {
        userId,
        revokedAt: null,
        ...(exceptSessionId && { id: { not: exceptSessionId } }),
      },
    });

    for (const session of sessions) {
      await this.revokeSession(session.id, reason || 'logout_all');
    }

    this.logger.log(
      `All sessions revoked for user ${userId} (${sessions.length} sessions)`,
    );

    return sessions.length;
  }

  /**
   * Get all active sessions for a user
   */
  async getActiveSessions(userId: string): Promise<SessionData[]> {
    const sessions = await this.prisma.session.findMany({
      where: {
        userId,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { lastActiveAt: 'desc' },
    });

    return sessions.map((session) => ({
      id: session.id,
      userId: session.userId,
      tenantId: session.tenantId,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      deviceInfo: session.deviceInfo as object,
      createdAt: session.createdAt,
      lastActiveAt: session.lastActiveAt,
      expiresAt: session.expiresAt,
    }));
  }

  /**
   * Cleanup expired sessions (for cron job)
   */
  async cleanupExpiredSessions(): Promise<number> {
    const result = await this.prisma.session.deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    });

    if (result.count > 0) {
      this.logger.log(`Deleted ${result.count} expired sessions`);
    }

    return result.count;
  }

  /**
   * Get session cookie configuration
   */
  getSessionCookieConfig() {
    return {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      maxAge: DEFAULT_SESSION_TTL * 1000,
      path: '/',
    };
  }
}
