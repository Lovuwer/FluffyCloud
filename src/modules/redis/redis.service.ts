import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

/**
 * Redis Session Storage Strategy:
 *
 * We use two key patterns:
 * 1. "session:{sessionId}" - stores the actual session data (JSON)
 * 2. "user_sessions:{userId}" - a Set containing all session IDs for a user
 *
 * This allows us to:
 * - Quickly retrieve a session by ID
 * - Invalidate all sessions for a user (logout everywhere)
 * - Automatically expire sessions via Redis TTL
 */
@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private client: Redis;
  private readonly sessionTtl: number;

  constructor(private configService: ConfigService) {
    const host = this.configService.get<string>('REDIS_HOST', 'localhost');
    const port = this.configService.get<number>('REDIS_PORT', 6379);
    const password = this.configService.get<string>('REDIS_PASSWORD', '');
    const db = this.configService.get<number>('REDIS_DB', 0);

    this.sessionTtl = this.configService.get<number>(
      'SESSION_TTL_SECONDS',
      86400,
    );

    this.client = new Redis({
      host,
      port,
      password: password || undefined,
      db,
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
    });
  }

  async onModuleInit() {
    try {
      await this.client.ping();
      console.log('🔴 Redis connected');
    } catch (error) {
      console.error('❌ Redis connection failed:', error);
    }
  }

  async onModuleDestroy() {
    await this.client.quit();
    console.log('🔴 Redis disconnected');
  }

  // Basic key-value operations
  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds) {
      await this.client.setex(key, ttlSeconds, value);
    } else {
      await this.client.set(key, value);
    }
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.client.exists(key);
    return result === 1;
  }

  // Session management
  private sessionKey(sessionId: string): string {
    return `session:${sessionId}`;
  }

  private userSessionsKey(userId: string): string {
    return `user_sessions:${userId}`;
  }

  async setSession(
    sessionId: string,
    data: object,
    ttlSeconds?: number,
  ): Promise<void> {
    const ttl = ttlSeconds ?? this.sessionTtl;
    const key = this.sessionKey(sessionId);
    await this.client.setex(key, ttl, JSON.stringify(data));

    // Track session in user's session set
    const userId = (data as { userId?: string }).userId;
    if (userId) {
      const userKey = this.userSessionsKey(userId);
      await this.client.sadd(userKey, sessionId);
      // Set TTL on user sessions set to clean up automatically
      await this.client.expire(userKey, ttl);
    }
  }

  async getSession<T = object>(sessionId: string): Promise<T | null> {
    const data = await this.client.get(this.sessionKey(sessionId));
    if (!data) return null;
    try {
      return JSON.parse(data) as T;
    } catch {
      return null;
    }
  }

  async invalidateSession(sessionId: string): Promise<void> {
    // Get session to find userId
    const session = await this.getSession<{ userId?: string }>(sessionId);
    if (session?.userId) {
      await this.client.srem(this.userSessionsKey(session.userId), sessionId);
    }
    await this.del(this.sessionKey(sessionId));
  }

  /**
   * Invalidate all sessions for a user (logout everywhere feature)
   * Uses SMEMBERS to get all session IDs for the user, then deletes each one
   */
  async invalidateUserSessions(userId: string): Promise<void> {
    const userKey = this.userSessionsKey(userId);
    const sessionIds = await this.client.smembers(userKey);

    // Delete all session keys
    if (sessionIds.length > 0) {
      const sessionKeys = sessionIds.map((id) => this.sessionKey(id));
      await this.client.del(...sessionKeys);
    }

    // Delete the user sessions set
    await this.client.del(userKey);
  }

  // Refresh token revocation tracking
  async setRevokedToken(jti: string, ttlSeconds: number): Promise<void> {
    await this.client.setex(`revoked_token:${jti}`, ttlSeconds, '1');
  }

  async isTokenRevoked(jti: string): Promise<boolean> {
    return this.exists(`revoked_token:${jti}`);
  }
}
