import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../../../database/prisma.service.js';
import { OAuthClientService } from './oauth-client.service.js';
import crypto from 'crypto';

interface AuthorizationParams {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}

/**
 * OAuth2 Authorization Service
 * Handles authorization code flow with PKCE support
 */
@Injectable()
export class AuthorizationService {
  constructor(
    private prisma: PrismaService,
    private oauthClientService: OAuthClientService,
  ) {}

  /**
   * Validate and initiate authorization request
   */
  async initiateAuthorization(params: AuthorizationParams, userId?: string) {
    // Validate response_type
    if (params.responseType !== 'code') {
      throw new BadRequestException('Only response_type=code is supported');
    }

    // Validate client exists and is active
    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId: params.clientId },
    });

    if (!client || !client.isActive) {
      // Don't redirect to untrusted URI - show error page
      throw new BadRequestException('Invalid client_id');
    }

    // Validate redirect_uri is in client's allowed list
    if (
      !this.oauthClientService.isRedirectUriAllowed(client, params.redirectUri)
    ) {
      // Don't redirect to untrusted URI - show error page
      throw new BadRequestException('Invalid redirect_uri');
    }

    // Validate requested scopes
    const requestedScopes = params.scope.split(' ').filter((s) => s.length > 0);
    if (!this.oauthClientService.areScopesAllowed(client, requestedScopes)) {
      throw new BadRequestException('Invalid scope');
    }

    // Validate PKCE if provided
    if (params.codeChallenge) {
      if (!params.codeChallengeMethod) {
        params.codeChallengeMethod = 'plain';
      }
      if (!['S256', 'plain'].includes(params.codeChallengeMethod)) {
        throw new BadRequestException(
          'Invalid code_challenge_method. Must be S256 or plain',
        );
      }
    } else if (!client.isConfidential) {
      // Log warning for public clients not using PKCE
      console.warn(
        `[SECURITY] Public client ${client.clientId} not using PKCE`,
      );
    }

    // Return authorization page data
    return {
      client: {
        id: client.id,
        clientId: client.clientId,
        name: client.name,
        description: client.description,
      },
      scopes: requestedScopes,
      redirectUri: params.redirectUri,
      state: params.state,
      codeChallenge: params.codeChallenge,
      codeChallengeMethod: params.codeChallengeMethod,
      requiresLogin: !userId,
    };
  }

  /**
   * Generate authorization code (32 bytes, base64url encoded)
   */
  private generateCode(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  /**
   * Create authorization code after user consent
   */
  async createAuthorizationCode(
    userId: string,
    tenantId: string,
    clientId: string,
    scope: string,
    redirectUri: string,
    codeChallenge?: string,
    codeChallengeMethod?: string,
  ): Promise<string> {
    const code = this.generateCode();

    // Codes expire in 10 minutes
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await this.prisma.authorizationCode.create({
      data: {
        code,
        clientId,
        userId,
        tenantId,
        redirectUri,
        scope,
        codeChallenge,
        codeChallengeMethod,
        expiresAt,
      },
    });

    console.log(
      `[AUDIT] Authorization code created for user ${userId}, client ${clientId}`,
    );

    return code;
  }

  /**
   * Validate authorization code during token exchange
   */
  async validateAuthorizationCode(
    code: string,
    clientId: string,
    redirectUri: string,
    codeVerifier?: string,
  ): Promise<{ userId: string; tenantId: string; scope: string }> {
    const authCode = await this.prisma.authorizationCode.findUnique({
      where: { code },
    });

    if (!authCode) {
      throw new UnauthorizedException('Invalid authorization code');
    }

    // Check not expired
    if (authCode.expiresAt < new Date()) {
      throw new UnauthorizedException('Authorization code has expired');
    }

    // Check not already used
    if (authCode.usedAt) {
      // Potential replay attack - revoke all tokens for this authorization
      console.error(`[SECURITY] Authorization code reuse detected: ${code}`);
      throw new UnauthorizedException(
        'Authorization code has already been used',
      );
    }

    // Validate client_id matches
    if (authCode.clientId !== clientId) {
      throw new UnauthorizedException('Client ID mismatch');
    }

    // Validate redirect_uri matches exactly
    if (authCode.redirectUri !== redirectUri) {
      throw new UnauthorizedException('Redirect URI mismatch');
    }

    // Verify PKCE if it was used
    if (authCode.codeChallenge) {
      if (!codeVerifier) {
        throw new UnauthorizedException('code_verifier required');
      }

      const isValid = this.verifyPkce(
        codeVerifier,
        authCode.codeChallenge,
        authCode.codeChallengeMethod || 'plain',
      );

      if (!isValid) {
        throw new UnauthorizedException('Invalid code_verifier');
      }
    }

    // Mark as used
    await this.prisma.authorizationCode.update({
      where: { id: authCode.id },
      data: { usedAt: new Date() },
    });

    return {
      userId: authCode.userId,
      tenantId: authCode.tenantId,
      scope: authCode.scope,
    };
  }

  /**
   * Verify PKCE code_verifier against code_challenge
   * For S256: code_challenge = base64url(sha256(code_verifier))
   */
  private verifyPkce(
    codeVerifier: string,
    codeChallenge: string,
    method: string,
  ): boolean {
    if (method === 'plain') {
      return codeVerifier === codeChallenge;
    }

    if (method === 'S256') {
      const hash = crypto.createHash('sha256').update(codeVerifier).digest();
      const computed = hash.toString('base64url');
      return computed === codeChallenge;
    }

    return false;
  }

  /**
   * Generate simple HTML consent page
   */
  generateConsentPage(
    clientName: string,
    scopes: string[],
    state?: string,
  ): string {
    const scopeList = scopes
      .map((s) => `<li>${this.escapeHtml(s)}</li>`)
      .join('');

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize Application</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
    h1 { color: #333; }
    .app-name { color: #0066cc; font-weight: bold; }
    .scopes { background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0; }
    .scopes ul { margin: 0; padding-left: 20px; }
    .buttons { display: flex; gap: 10px; margin-top: 20px; }
    button { padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; }
    .approve { background: #0066cc; color: white; }
    .deny { background: #ccc; color: #333; }
  </style>
</head>
<body>
  <h1>Authorize Application</h1>
  <p><span class="app-name">${this.escapeHtml(clientName)}</span> is requesting access to your account.</p>
  
  <div class="scopes">
    <strong>This application will be able to:</strong>
    <ul>${scopeList}</ul>
  </div>

  <form method="POST" action="/oauth/authorize/consent">
    <input type="hidden" name="state" value="${this.escapeHtml(state || '')}">
    <div class="buttons">
      <button type="submit" name="action" value="approve" class="approve">Approve</button>
      <button type="submit" name="action" value="deny" class="deny">Deny</button>
    </div>
  </form>
</body>
</html>`;
  }

  /**
   * Generate error page HTML
   */
  generateErrorPage(error: string, description: string): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorization Error</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
    h1 { color: #cc0000; }
    .error { background: #fff0f0; padding: 15px; border-radius: 8px; border: 1px solid #ffcccc; }
  </style>
</head>
<body>
  <h1>Authorization Error</h1>
  <div class="error">
    <strong>Error:</strong> ${this.escapeHtml(error)}<br>
    <p>${this.escapeHtml(description)}</p>
  </div>
</body>
</html>`;
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}
