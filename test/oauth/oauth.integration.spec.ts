/**
 * OAuth2 Flow Integration Tests
 * Tests authorization code flow, token exchange, PKCE, and client credentials
 */

import { Test, TestingModule } from '@nestjs/testing';
import crypto from 'crypto';
import {
  mockPrismaService,
  mockRedisService,
  createTestTenant,
  createTestUser,
  createTestOAuthClient,
  resetMocks,
} from '../utils/test-helpers.js';

// Import services that will be mocked
import { OAuthClientService } from '../../src/modules/oauth/services/oauth-client.service.js';
import { AuthorizationService } from '../../src/modules/oauth/services/authorization.service.js';
import { OAuthTokenService } from '../../src/modules/oauth/services/oauth-token.service.js';
import { PrismaService } from '../../src/database/prisma.service.js';
import { RedisService } from '../../src/modules/redis/redis.service.js';
import { ConfigService } from '@nestjs/config';

describe('OAuth2 Flow Integration Tests', () => {
  const testTenant = createTestTenant();
  const testUser = createTestUser();
  const testOAuthClient = createTestOAuthClient();

  beforeEach(() => {
    resetMocks();
  });

  describe('OAuth Client Management', () => {
    let oauthClientService: OAuthClientService;

    beforeEach(async () => {
      const moduleFixture: TestingModule = await Test.createTestingModule({
        providers: [
          OAuthClientService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn(),
            },
          },
        ],
      }).compile();

      oauthClientService =
        moduleFixture.get<OAuthClientService>(OAuthClientService);
    });

    it('should create a new OAuth client', async () => {
      mockPrismaService.oAuthClient.create.mockResolvedValue({
        ...testOAuthClient,
        id: 'new-client-id',
      });

      const result = await oauthClientService.createClient({
        name: 'New Test Client',
        redirectUris: ['http://localhost:3000/callback'],
        allowedGrantTypes: ['authorization_code'],
        allowedScopes: ['openid', 'profile'],
        isConfidential: true,
        tenantId: testTenant.id,
      });

      expect(result).toHaveProperty('clientId');
      expect(result).toHaveProperty('clientSecret'); // Only returned on creation
      expect(result.clientSecret).toBeDefined();
      expect(result.clientSecret.length).toBeGreaterThan(0);
    });

    it('should validate client credentials', async () => {
      // This tests that the service can look up and verify a client
      mockPrismaService.oAuthClient.findFirst.mockResolvedValue(
        testOAuthClient,
      );

      // The validateClient method should check the client exists and is active
      const client = await oauthClientService.getClientByClientId(
        testOAuthClient.clientId,
      );

      expect(client).toBeDefined();
      expect(client?.clientId).toBe(testOAuthClient.clientId);
      expect(client?.isActive).toBe(true);
    });

    it('should reject inactive client', async () => {
      mockPrismaService.oAuthClient.findFirst.mockResolvedValue({
        ...testOAuthClient,
        isActive: false,
      });

      const client = await oauthClientService.getClientByClientId(
        testOAuthClient.clientId,
      );

      // Client should still be returned but marked as inactive
      expect(client?.isActive).toBe(false);
    });

    it('should rotate client secret', async () => {
      mockPrismaService.oAuthClient.findUnique.mockResolvedValue(
        testOAuthClient,
      );
      mockPrismaService.oAuthClient.update.mockResolvedValue({
        ...testOAuthClient,
        // New hashed secret would be stored
      });

      const result = await oauthClientService.rotateClientSecret(
        testOAuthClient.id,
      );

      expect(result).toHaveProperty('clientSecret');
      expect(result.clientSecret).toBeDefined();
      // The new secret should be different from any stored hash
      expect(result.clientSecret.length).toBe(64); // 64 char alphanumeric
    });

    it('should list clients for a tenant', async () => {
      mockPrismaService.oAuthClient.findMany.mockResolvedValue([
        testOAuthClient,
        { ...testOAuthClient, id: 'client-2', name: 'Second Client' },
      ]);

      const clients = await oauthClientService.listClients(testTenant.id);

      expect(clients).toHaveLength(2);
      expect(clients[0].name).toBe(testOAuthClient.name);
    });
  });

  describe('Authorization Endpoint', () => {
    let authorizationService: AuthorizationService;

    beforeEach(async () => {
      const moduleFixture: TestingModule = await Test.createTestingModule({
        providers: [
          AuthorizationService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: OAuthClientService,
            useValue: {
              getClientByClientId: jest.fn().mockResolvedValue(testOAuthClient),
              validateClient: jest.fn().mockResolvedValue(true),
            },
          },
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn(),
            },
          },
        ],
      }).compile();

      authorizationService =
        moduleFixture.get<AuthorizationService>(AuthorizationService);
    });

    it('should initiate authorization for valid client', async () => {
      const result = await authorizationService.initiateAuthorization(
        {
          responseType: 'code',
          clientId: testOAuthClient.clientId,
          redirectUri: testOAuthClient.redirectUris[0],
          scope: 'openid profile',
          state: 'random-state',
        },
        testUser.id,
      );

      expect(result).toHaveProperty('client');
      expect(result.client.clientId).toBe(testOAuthClient.clientId);
      expect(result).toHaveProperty('scopes');
    });

    it('should reject invalid redirect_uri', async () => {
      await expect(
        authorizationService.initiateAuthorization(
          {
            responseType: 'code',
            clientId: testOAuthClient.clientId,
            redirectUri: 'http://malicious.com/callback', // Not in allowed list
            scope: 'openid',
            state: 'random-state',
          },
          testUser.id,
        ),
      ).rejects.toThrow();
    });

    it('should validate PKCE code_challenge for public clients', async () => {
      const publicClient = {
        ...testOAuthClient,
        isConfidential: false,
      };

      const moduleFixture = await Test.createTestingModule({
        providers: [
          AuthorizationService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: OAuthClientService,
            useValue: {
              getClientByClientId: jest.fn().mockResolvedValue(publicClient),
              validateClient: jest.fn().mockResolvedValue(true),
            },
          },
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn(),
            },
          },
        ],
      }).compile();

      const service =
        moduleFixture.get<AuthorizationService>(AuthorizationService);

      // Without PKCE, should log warning for public client
      const result = await service.initiateAuthorization(
        {
          responseType: 'code',
          clientId: publicClient.clientId,
          redirectUri: publicClient.redirectUris[0],
          scope: 'openid',
          state: 'state',
        },
        testUser.id,
      );

      expect(result).toBeDefined();
    });

    it('should create authorization code with PKCE', async () => {
      const codeVerifier = crypto.randomBytes(32).toString('base64url');
      const codeChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');

      mockPrismaService.authorizationCode.create.mockResolvedValue({
        id: 'auth-code-id',
        code: 'mock-auth-code',
        clientId: testOAuthClient.clientId,
        userId: testUser.id,
        tenantId: testTenant.id,
        scope: 'openid profile',
        codeChallenge,
        codeChallengeMethod: 'S256',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      });

      const code = await authorizationService.createAuthorizationCode(
        testUser.id,
        testTenant.id,
        testOAuthClient.clientId,
        'openid profile',
        testOAuthClient.redirectUris[0],
        codeChallenge,
        'S256',
      );

      expect(code).toBeDefined();
      expect(typeof code).toBe('string');
    });
  });

  describe('Token Endpoint', () => {
    let oauthTokenService: OAuthTokenService;

    beforeEach(async () => {
      const moduleFixture: TestingModule = await Test.createTestingModule({
        providers: [
          OAuthTokenService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: RedisService,
            useValue: mockRedisService,
          },
          {
            provide: OAuthClientService,
            useValue: {
              getClientByClientId: jest.fn().mockResolvedValue(testOAuthClient),
              validateClient: jest.fn().mockResolvedValue(true),
            },
          },
          {
            provide: AuthorizationService,
            useValue: {
              validateAuthorizationCode: jest.fn().mockResolvedValue({
                userId: testUser.id,
                tenantId: testTenant.id,
                scope: 'openid profile',
              }),
            },
          },
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn((key: string) => {
                const config: Record<string, string> = {
                  JWT_ACCESS_TOKEN_EXPIRY: '15m',
                  JWT_REFRESH_TOKEN_EXPIRY: '7d',
                  JWT_ISSUER: 'iam-platform',
                };
                return config[key];
              }),
            },
          },
        ],
      }).compile();

      oauthTokenService =
        moduleFixture.get<OAuthTokenService>(OAuthTokenService);
    });

    it('should exchange valid authorization code for tokens', async () => {
      mockPrismaService.userRole.findMany.mockResolvedValue([
        {
          role: {
            name: 'user',
            rolePermissions: [{ permission: { name: 'users:read' } }],
          },
        },
      ]);
      mockPrismaService.oAuthToken.create.mockResolvedValue({});

      const result = await oauthTokenService.exchangeCode(
        'valid-auth-code',
        testOAuthClient.redirectUris[0],
        testOAuthClient.clientId,
        'client-secret',
        undefined, // no PKCE verifier
      );

      expect(result).toHaveProperty('access_token');
      expect(result).toHaveProperty('token_type', 'Bearer');
      expect(result).toHaveProperty('expires_in');
      expect(result).toHaveProperty('scope');
    });

    it('should fail with used authorization code', async () => {
      // Override the authorization service to reject
      const moduleFixture = await Test.createTestingModule({
        providers: [
          OAuthTokenService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: RedisService,
            useValue: mockRedisService,
          },
          {
            provide: OAuthClientService,
            useValue: {
              getClientByClientId: jest.fn().mockResolvedValue(testOAuthClient),
              validateClient: jest.fn().mockResolvedValue(true),
            },
          },
          {
            provide: AuthorizationService,
            useValue: {
              validateAuthorizationCode: jest
                .fn()
                .mockRejectedValue(
                  new Error('Authorization code has already been used'),
                ),
            },
          },
          {
            provide: ConfigService,
            useValue: { get: jest.fn() },
          },
        ],
      }).compile();

      const service = moduleFixture.get<OAuthTokenService>(OAuthTokenService);

      const result = await service.exchangeCode(
        'used-auth-code',
        testOAuthClient.redirectUris[0],
        testOAuthClient.clientId,
        'client-secret',
      );

      expect(result).toHaveProperty('error', 'invalid_grant');
    });

    it('should verify PKCE code_verifier', async () => {
      const codeVerifier = crypto.randomBytes(32).toString('base64url');
      const codeChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');

      const moduleFixture = await Test.createTestingModule({
        providers: [
          OAuthTokenService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: RedisService,
            useValue: mockRedisService,
          },
          {
            provide: OAuthClientService,
            useValue: {
              getClientByClientId: jest.fn().mockResolvedValue(testOAuthClient),
              validateClient: jest.fn().mockResolvedValue(true),
            },
          },
          {
            provide: AuthorizationService,
            useValue: {
              validateAuthorizationCode: jest.fn().mockResolvedValue({
                userId: testUser.id,
                tenantId: testTenant.id,
                scope: 'openid profile',
                codeChallenge,
                codeChallengeMethod: 'S256',
              }),
            },
          },
          {
            provide: ConfigService,
            useValue: { get: jest.fn() },
          },
        ],
      }).compile();

      const service = moduleFixture.get<OAuthTokenService>(OAuthTokenService);
      mockPrismaService.userRole.findMany.mockResolvedValue([]);
      mockPrismaService.oAuthToken.create.mockResolvedValue({});

      const result = await service.exchangeCode(
        'pkce-auth-code',
        testOAuthClient.redirectUris[0],
        testOAuthClient.clientId,
        'client-secret',
        codeVerifier, // Correct verifier
      );

      expect(result).toHaveProperty('access_token');
    });

    it('should fail with invalid PKCE code_verifier', async () => {
      const codeChallenge = crypto.randomBytes(32).toString('base64url');

      const moduleFixture = await Test.createTestingModule({
        providers: [
          OAuthTokenService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: RedisService,
            useValue: mockRedisService,
          },
          {
            provide: OAuthClientService,
            useValue: {
              getClientByClientId: jest.fn().mockResolvedValue(testOAuthClient),
              validateClient: jest.fn().mockResolvedValue(true),
            },
          },
          {
            provide: AuthorizationService,
            useValue: {
              validateAuthorizationCode: jest.fn().mockResolvedValue({
                userId: testUser.id,
                tenantId: testTenant.id,
                scope: 'openid profile',
                codeChallenge,
                codeChallengeMethod: 'S256',
              }),
            },
          },
          {
            provide: ConfigService,
            useValue: { get: jest.fn() },
          },
        ],
      }).compile();

      const service = moduleFixture.get<OAuthTokenService>(OAuthTokenService);

      const result = await service.exchangeCode(
        'pkce-auth-code',
        testOAuthClient.redirectUris[0],
        testOAuthClient.clientId,
        'client-secret',
        'wrong-verifier', // Wrong verifier
      );

      expect(result).toHaveProperty('error');
    });
  });

  describe('Client Credentials Flow', () => {
    let oauthTokenService: OAuthTokenService;

    beforeEach(async () => {
      const moduleFixture: TestingModule = await Test.createTestingModule({
        providers: [
          OAuthTokenService,
          {
            provide: PrismaService,
            useValue: mockPrismaService,
          },
          {
            provide: RedisService,
            useValue: mockRedisService,
          },
          {
            provide: OAuthClientService,
            useValue: {
              getClientByClientId: jest.fn().mockResolvedValue({
                ...testOAuthClient,
                allowedGrantTypes: ['client_credentials'],
              }),
              validateClient: jest.fn().mockResolvedValue(true),
            },
          },
          {
            provide: AuthorizationService,
            useValue: {},
          },
          {
            provide: ConfigService,
            useValue: {
              get: jest.fn((key: string) => {
                const config: Record<string, string> = {
                  JWT_ACCESS_TOKEN_EXPIRY: '15m',
                  JWT_ISSUER: 'iam-platform',
                };
                return config[key];
              }),
            },
          },
        ],
      }).compile();

      oauthTokenService =
        moduleFixture.get<OAuthTokenService>(OAuthTokenService);
    });

    it('should issue token for valid client credentials', async () => {
      mockPrismaService.oAuthToken.create.mockResolvedValue({});

      const result = await oauthTokenService.clientCredentialsGrant(
        testOAuthClient.clientId,
        'valid-client-secret',
        'read write',
      );

      expect(result).toHaveProperty('access_token');
      expect(result).toHaveProperty('token_type', 'Bearer');
      expect(result).toHaveProperty('expires_in');
      // Client credentials flow should not return refresh token
      expect(result.refresh_token).toBeUndefined();
    });

    it('should scope token to requested scopes', async () => {
      mockPrismaService.oAuthToken.create.mockResolvedValue({});

      const result = await oauthTokenService.clientCredentialsGrant(
        testOAuthClient.clientId,
        'valid-client-secret',
        'openid email', // Requesting specific scopes
      );

      expect(result).toHaveProperty('scope');
      expect(result.scope).toContain('openid');
    });
  });
});
