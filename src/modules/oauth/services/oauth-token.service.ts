import { Injectable, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../../database/prisma.service.js';
import { OAuthClientService } from './oauth-client.service.js';
import { AuthorizationService } from './authorization.service.js';
import { TokenService } from '../../auth/services/token.service.js';
import { v4 as uuidv4 } from 'uuid';

interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope: string;
}

interface OAuthError {
  error: string;
  error_description: string;
}

/**
 * OAuth2 Token Service
 * Handles token exchange, refresh, and revocation
 */
@Injectable()
export class OAuthTokenService {
  constructor(
    private prisma: PrismaService,
    private oauthClientService: OAuthClientService,
    private authorizationService: AuthorizationService,
    private tokenService: TokenService,
  ) {}

  /**
   * Exchange authorization code for tokens
   */
  async exchangeCode(
    code: string,
    redirectUri: string,
    clientId: string,
    clientSecret?: string,
    codeVerifier?: string,
  ): Promise<TokenResponse> {
    // Validate client
    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId },
    });

    if (!client || !client.isActive) {
      throw this.createOAuthError(
        'invalid_client',
        'Unknown or inactive client',
      );
    }

    // For confidential clients, verify secret
    if (client.isConfidential) {
      if (!clientSecret) {
        throw this.createOAuthError(
          'invalid_client',
          'Client authentication required',
        );
      }
      const isValid = await this.oauthClientService.validateClient(
        clientId,
        clientSecret,
      );
      if (!isValid) {
        throw this.createOAuthError(
          'invalid_client',
          'Invalid client credentials',
        );
      }
    }

    // Validate authorization code
    const { userId, tenantId, scope } = await this.authorizationService
      .validateAuthorizationCode(code, clientId, redirectUri, codeVerifier)
      .catch(() => {
        throw this.createOAuthError(
          'invalid_grant',
          'Invalid or expired authorization code',
        );
      });

    // Get user info for token
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.isActive) {
      throw this.createOAuthError(
        'invalid_grant',
        'User not found or inactive',
      );
    }

    // Get user roles and permissions
    const userRoles = await this.prisma.userRole.findMany({
      where: { userId: user.id },
      include: {
        role: {
          include: {
            rolePermissions: {
              include: {
                permission: true,
              },
            },
          },
        },
      },
    });

    const roles = userRoles.map((ur) => ur.role.name);
    const permissions = [
      ...new Set(
        userRoles.flatMap((ur) =>
          ur.role.rolePermissions.map((rp) => rp.permission.name),
        ),
      ),
    ];

    // Generate tokens
    const accessTokenJti = uuidv4();
    const refreshTokenJti = uuidv4();

    const accessToken = this.tokenService.generateAccessToken(
      { id: user.id, email: user.email },
      tenantId,
      roles,
      permissions,
    );

    const refreshToken = await this.tokenService.generateRefreshToken(
      user.id,
      tenantId,
    );

    // Store token record
    const expiresIn = this.tokenService.getAccessTokenExpirySeconds();
    const expiresAt = new Date(Date.now() + expiresIn * 1000);
    const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await this.prisma.oAuthToken.create({
      data: {
        clientId,
        userId,
        tenantId,
        accessTokenJti,
        refreshTokenJti,
        scope,
        expiresAt,
        refreshExpiresAt,
      },
    });

    console.log(
      `[AUDIT] OAuth tokens issued for user ${userId}, client ${clientId}`,
    );

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refreshToken,
      scope,
    };
  }

  /**
   * Refresh access token
   */
  async refreshAccessToken(
    refreshToken: string,
    clientId: string,
    clientSecret?: string,
  ): Promise<TokenResponse> {
    // Validate client
    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId },
    });

    if (!client || !client.isActive) {
      throw this.createOAuthError(
        'invalid_client',
        'Unknown or inactive client',
      );
    }

    // For confidential clients, verify secret
    if (client.isConfidential) {
      if (!clientSecret) {
        throw this.createOAuthError(
          'invalid_client',
          'Client authentication required',
        );
      }
      const isValid = await this.oauthClientService.validateClient(
        clientId,
        clientSecret,
      );
      if (!isValid) {
        throw this.createOAuthError(
          'invalid_client',
          'Invalid client credentials',
        );
      }
    }

    // Verify refresh token
    const payload = await this.tokenService
      .verifyRefreshToken(refreshToken)
      .catch(() => {
        throw this.createOAuthError(
          'invalid_grant',
          'Invalid or expired refresh token',
        );
      });

    // Get user
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user || !user.isActive) {
      throw this.createOAuthError(
        'invalid_grant',
        'User not found or inactive',
      );
    }

    // Get user roles and permissions
    const userRoles = await this.prisma.userRole.findMany({
      where: { userId: user.id },
      include: {
        role: {
          include: {
            rolePermissions: {
              include: {
                permission: true,
              },
            },
          },
        },
      },
    });

    const roles = userRoles.map((ur) => ur.role.name);
    const permissions = [
      ...new Set(
        userRoles.flatMap((ur) =>
          ur.role.rolePermissions.map((rp) => rp.permission.name),
        ),
      ),
    ];

    // Revoke old refresh token
    await this.tokenService.revokeRefreshToken(payload.jti);

    // Generate new tokens
    const accessToken = this.tokenService.generateAccessToken(
      { id: user.id, email: user.email },
      payload.tenantId,
      roles,
      permissions,
    );

    const newRefreshToken = await this.tokenService.generateRefreshToken(
      user.id,
      payload.tenantId,
    );

    // Find and update token record
    const existingToken = await this.prisma.oAuthToken.findFirst({
      where: {
        clientId,
        userId: user.id,
        revokedAt: null,
      },
      orderBy: { createdAt: 'desc' },
    });

    if (existingToken) {
      const newAccessTokenJti = uuidv4();
      const newRefreshTokenJti = uuidv4();
      const tokenExpiresIn = this.tokenService.getAccessTokenExpirySeconds();
      const expiresAt = new Date(Date.now() + tokenExpiresIn * 1000);
      const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      await this.prisma.oAuthToken.update({
        where: { id: existingToken.id },
        data: {
          accessTokenJti: newAccessTokenJti,
          refreshTokenJti: newRefreshTokenJti,
          expiresAt,
          refreshExpiresAt,
        },
      });
    }

    console.log(
      `[AUDIT] OAuth tokens refreshed for user ${user.id}, client ${clientId}`,
    );

    const expiresIn = this.tokenService.getAccessTokenExpirySeconds();
    const scope = existingToken?.scope || 'openid profile';

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: newRefreshToken,
      scope,
    };
  }

  /**
   * Client credentials grant (machine-to-machine)
   */
  async clientCredentialsGrant(
    clientId: string,
    clientSecret: string,
    scope: string,
  ): Promise<TokenResponse> {
    // Validate client
    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId },
    });

    if (!client || !client.isActive) {
      throw this.createOAuthError(
        'invalid_client',
        'Unknown or inactive client',
      );
    }

    if (!client.isConfidential) {
      throw this.createOAuthError(
        'unauthorized_client',
        'Client credentials grant requires confidential client',
      );
    }

    // Verify secret
    const isValid = await this.oauthClientService.validateClient(
      clientId,
      clientSecret,
    );
    if (!isValid) {
      throw this.createOAuthError(
        'invalid_client',
        'Invalid client credentials',
      );
    }

    // Validate scopes
    const requestedScopes = scope.split(' ').filter((s) => s.length > 0);
    if (!this.oauthClientService.areScopesAllowed(client, requestedScopes)) {
      throw this.createOAuthError(
        'invalid_scope',
        'Requested scope is not allowed',
      );
    }

    // Generate access token only (no user context, no refresh token)
    const accessTokenJti = uuidv4();

    // For client credentials, we use the client as the "user"
    const accessToken = this.tokenService.generateAccessToken(
      { id: clientId, email: `${clientId}@client.local` },
      client.tenantId || 'system',
      ['client'],
      requestedScopes,
    );

    // Store token record
    const expiresIn = this.tokenService.getAccessTokenExpirySeconds();
    const expiresAt = new Date(Date.now() + expiresIn * 1000);

    await this.prisma.oAuthToken.create({
      data: {
        clientId,
        userId: null,
        tenantId: client.tenantId,
        accessTokenJti,
        refreshTokenJti: null,
        scope,
        expiresAt,
        refreshExpiresAt: null,
      },
    });

    console.log(
      `[AUDIT] OAuth client credentials token issued for client ${clientId}`,
    );

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      scope,
    };
  }

  /**
   * Revoke a token (access or refresh)
   * Per RFC 7009 - always return 200 even if token invalid
   */
  async revokeToken(token: string, _tokenTypeHint?: string): Promise<void> {
    try {
      // Try to decode as refresh token first
      const payload = await this.tokenService
        .verifyRefreshToken(token)
        .catch(() => null);

      if (payload) {
        await this.tokenService.revokeRefreshToken(payload.jti);

        // Mark token record as revoked
        await this.prisma.oAuthToken.updateMany({
          where: { refreshTokenJti: payload.jti },
          data: { revokedAt: new Date() },
        });

        console.log(`[AUDIT] Refresh token revoked: ${payload.jti}`);
      }
    } catch {
      // Per RFC 7009, we always return 200
    }
  }

  /**
   * Token introspection per RFC 7662
   */
  async introspectToken(
    token: string,
    clientId: string,
    clientSecret: string,
  ): Promise<{ active: boolean; [key: string]: unknown }> {
    // Validate client
    const isValid = await this.oauthClientService.validateClient(
      clientId,
      clientSecret,
    );
    if (!isValid) {
      throw this.createOAuthError(
        'invalid_client',
        'Invalid client credentials',
      );
    }

    try {
      const payload = this.tokenService.verifyAccessToken(token);

      return {
        active: true,
        sub: payload.sub,
        client_id: clientId,
        email: payload.email,
        tenant_id: payload.tenantId,
        roles: payload.roles,
        permissions: payload.permissions,
        token_type: 'Bearer',
        exp: payload.exp,
        iat: payload.iat,
        iss: payload.iss,
      };
    } catch {
      return { active: false };
    }
  }

  /**
   * Create OAuth error response
   */
  private createOAuthError(
    error: string,
    description: string,
  ): BadRequestException {
    const errorResponse: OAuthError = {
      error,
      error_description: description,
    };
    return new BadRequestException(errorResponse);
  }
}
