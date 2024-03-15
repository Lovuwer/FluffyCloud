import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import { RedisService } from '../../redis/redis.service.js';

/**
 * JWT Token Service using RS256 (asymmetric) signing
 *
 * Why RS256 over HS256?
 * 1. Key rotation: Can rotate keys without invalidating all tokens
 * 2. Public key verification: Services can verify tokens without knowing the private key
 * 3. Better security: Private key stays on auth server only
 * 4. Microservices: Other services only need the public key to verify
 */

interface AccessTokenPayload {
  sub: string; // userId
  email: string;
  tenantId: string;
  roles: string[];
  permissions: string[];
  type: 'access';
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string;
}

interface RefreshTokenPayload {
  sub: string; // userId
  tenantId: string;
  type: 'refresh';
  jti: string; // Unique token ID for revocation
  iat?: number;
  exp?: number;
  iss?: string;
}

@Injectable()
export class TokenService {
  private privateKey: string;
  private publicKey: string;
  private readonly accessTokenExpiry: string;
  private readonly refreshTokenExpiry: string;
  private readonly issuer: string;

  constructor(
    private configService: ConfigService,
    private redisService: RedisService,
  ) {
    // Load keys from file or env var
    this.privateKey = this.loadKey('JWT_PRIVATE_KEY', 'JWT_PRIVATE_KEY_PATH');
    this.publicKey = this.loadKey('JWT_PUBLIC_KEY', 'JWT_PUBLIC_KEY_PATH');

    this.accessTokenExpiry = this.configService.get<string>(
      'JWT_ACCESS_TOKEN_EXPIRY',
      '15m',
    );
    this.refreshTokenExpiry = this.configService.get<string>(
      'JWT_REFRESH_TOKEN_EXPIRY',
      '7d',
    );
    this.issuer = this.configService.get<string>('JWT_ISSUER', 'iam-platform');
  }

  private loadKey(envKey: string, pathEnvKey: string): string {
    // First try to load from env var directly
    const keyValue = this.configService.get<string>(envKey);
    if (keyValue) {
      return keyValue;
    }

    // Then try to load from file path
    const keyPath = this.configService.get<string>(pathEnvKey);
    if (keyPath) {
      try {
        const absolutePath = path.isAbsolute(keyPath)
          ? keyPath
          : path.join(process.cwd(), keyPath);
        return fs.readFileSync(absolutePath, 'utf8');
      } catch (error) {
        console.warn(`Warning: Could not load key from ${keyPath}:`, error);
      }
    }

    // Return empty string if no key found (will fail on token operations)
    console.warn(
      `Warning: No ${envKey} or ${pathEnvKey} configured. JWT operations will fail until keys are configured.`,
    );
    return '';
  }

  generateAccessToken(
    user: { id: string; email: string },
    tenantId: string,
    roles: string[],
    permissions: string[],
  ): string {
    if (!this.privateKey) {
      throw new Error('JWT private key not configured');
    }

    const payload: AccessTokenPayload = {
      sub: user.id,
      email: user.email,
      tenantId,
      roles,
      permissions,
      type: 'access',
    };

    return jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      expiresIn: this.parseExpiryToSeconds(this.accessTokenExpiry),
      issuer: this.issuer,
    });
  }

  async generateRefreshToken(
    userId: string,
    tenantId: string,
  ): Promise<string> {
    if (!this.privateKey) {
      throw new Error('JWT private key not configured');
    }

    const jti = uuidv4(); // Unique token ID for revocation tracking

    const payload: RefreshTokenPayload = {
      sub: userId,
      tenantId,
      type: 'refresh',
      jti,
    };

    const token = jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      expiresIn: this.parseExpiryToSeconds(this.refreshTokenExpiry),
      issuer: this.issuer,
    });

    // Store jti in Redis with TTL matching token expiry for revocation checking
    const ttlSeconds = this.parseExpiryToSeconds(this.refreshTokenExpiry);
    await this.redisService.set(`refresh_token:${jti}`, userId, ttlSeconds);

    return token;
  }

  verifyAccessToken(token: string): AccessTokenPayload {
    if (!this.publicKey) {
      throw new Error('JWT public key not configured');
    }

    try {
      const decoded = jwt.verify(token, this.publicKey, {
        algorithms: ['RS256'],
        issuer: this.issuer,
      }) as AccessTokenPayload;

      if (decoded.type !== 'access') {
        throw new UnauthorizedException('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new UnauthorizedException('Token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new UnauthorizedException('Invalid token');
      }
      throw error;
    }
  }

  async verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    if (!this.publicKey) {
      throw new Error('JWT public key not configured');
    }

    try {
      const decoded = jwt.verify(token, this.publicKey, {
        algorithms: ['RS256'],
        issuer: this.issuer,
      }) as RefreshTokenPayload;

      if (decoded.type !== 'refresh') {
        throw new UnauthorizedException('Invalid token type');
      }

      // Check if token has been revoked
      const isRevoked = await this.isRefreshTokenRevoked(decoded.jti);
      if (isRevoked) {
        throw new UnauthorizedException('Token has been revoked');
      }

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new UnauthorizedException('Refresh token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      throw error;
    }
  }

  async revokeRefreshToken(jti: string): Promise<void> {
    // Mark token as revoked in Redis
    await this.redisService.setRevokedToken(
      jti,
      this.parseExpiryToSeconds(this.refreshTokenExpiry),
    );
    // Also remove from active tokens
    await this.redisService.del(`refresh_token:${jti}`);
  }

  async isRefreshTokenRevoked(jti: string): Promise<boolean> {
    return this.redisService.isTokenRevoked(jti);
  }

  /**
   * Extract Bearer token from Authorization header
   */
  extractTokenFromHeader(authHeader: string | undefined): string | null {
    if (!authHeader) return null;

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return null;
    }

    return parts[1];
  }

  private parseExpiryToSeconds(expiry: string): number {
    const match = expiry.match(/^(\d+)(s|m|h|d)$/);
    if (!match) {
      return 3600; // Default 1 hour
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 3600;
      case 'd':
        return value * 86400;
      default:
        return 3600;
    }
  }

  /**
   * Get access token expiry time in seconds
   */
  getAccessTokenExpirySeconds(): number {
    return this.parseExpiryToSeconds(this.accessTokenExpiry);
  }
}
