import {
  Controller,
  Post,
  Get,
  Query,
  Body,
  Res,
  HttpCode,
  HttpStatus,
  UseGuards,
  Headers,
} from '@nestjs/common';
import type { Response } from 'express';
import { AuthorizationService } from './services/authorization.service.js';
import { OAuthTokenService } from './services/oauth-token.service.js';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard.js';
import { Public } from '../../common/decorators/public.decorator.js';
import { CurrentUser } from '../../common/decorators/current-user.decorator.js';

interface RequestUser {
  userId: string;
  tenantId: string;
  roles: string[];
}

interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope: string;
}

// TODO: Add rate limiting on token endpoint

/**
 * OAuth2 Authorization and Token Controller
 * Implements OAuth2 authorization code flow with PKCE support
 */
@Controller('oauth')
export class OAuthController {
  constructor(
    private authorizationService: AuthorizationService,
    private oauthTokenService: OAuthTokenService,
  ) {}

  /**
   * Authorization endpoint
   * GET /oauth/authorize
   */
  @Get('authorize')
  @UseGuards(JwtAuthGuard)
  async authorize(
    @Query('response_type') responseType: string,
    @Query('client_id') clientId: string,
    @Query('redirect_uri') redirectUri: string,
    @Query('scope') scope: string,
    @Query('state') state: string,
    @Query('code_challenge') codeChallenge: string,
    @Query('code_challenge_method') codeChallengeMethod: string,
    @CurrentUser() user: RequestUser | undefined,
    @Res() res: Response,
  ) {
    try {
      const authData = await this.authorizationService.initiateAuthorization(
        {
          responseType,
          clientId,
          redirectUri,
          scope: scope || '',
          state,
          codeChallenge,
          codeChallengeMethod,
        },
        user?.userId,
      );

      // If user not logged in, redirect to login
      if (authData.requiresLogin) {
        const returnUrl = encodeURIComponent(
          `/oauth/authorize?response_type=${responseType}&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scope || '')}&state=${state || ''}&code_challenge=${codeChallenge || ''}&code_challenge_method=${codeChallengeMethod || ''}`,
        );
        return res.redirect(`/auth/login?returnUrl=${returnUrl}`);
      }

      // Show consent page
      const consentHtml = this.authorizationService.generateConsentPage(
        authData.client.name,
        authData.scopes,
        state,
      );

      // Store authorization data in session/cookie for consent POST
      // For now, we'll pass it via hidden form fields
      res.setHeader('Content-Type', 'text/html');
      return res.send(
        consentHtml.replace(
          '</form>',
          `<input type="hidden" name="client_id" value="${clientId}">
           <input type="hidden" name="redirect_uri" value="${redirectUri}">
           <input type="hidden" name="scope" value="${scope || ''}">
           <input type="hidden" name="code_challenge" value="${codeChallenge || ''}">
           <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod || ''}">
           </form>`,
        ),
      );
    } catch (error) {
      // Show error page (don't redirect to untrusted URI)
      const errorHtml = this.authorizationService.generateErrorPage(
        'invalid_request',
        error instanceof Error ? error.message : 'Authorization failed',
      );
      res.setHeader('Content-Type', 'text/html');
      return res.status(400).send(errorHtml);
    }
  }

  /**
   * Handle user consent submission
   * POST /oauth/authorize/consent
   */
  @Post('authorize/consent')
  @UseGuards(JwtAuthGuard)
  async handleConsent(
    @Body('action') action: string,
    @Body('client_id') clientId: string,
    @Body('redirect_uri') redirectUri: string,
    @Body('scope') scope: string,
    @Body('state') state: string,
    @Body('code_challenge') codeChallenge: string,
    @Body('code_challenge_method') codeChallengeMethod: string,
    @CurrentUser() user: RequestUser,
    @Res() res: Response,
  ) {
    if (action === 'deny') {
      // User denied - redirect with error
      const errorUrl = `${redirectUri}?error=access_denied&error_description=User%20denied%20consent${state ? `&state=${state}` : ''}`;
      return res.redirect(errorUrl);
    }

    try {
      // Create authorization code
      const code = await this.authorizationService.createAuthorizationCode(
        user.userId,
        user.tenantId,
        clientId,
        scope,
        redirectUri,
        codeChallenge || undefined,
        codeChallengeMethod || undefined,
      );

      // Redirect with code
      const successUrl = `${redirectUri}?code=${code}${state ? `&state=${state}` : ''}`;
      return res.redirect(successUrl);
    } catch {
      const errorUrl = `${redirectUri}?error=server_error&error_description=Failed%20to%20create%20authorization%20code${state ? `&state=${state}` : ''}`;
      return res.redirect(errorUrl);
    }
  }

  /**
   * Token endpoint
   * POST /oauth/token
   * Content-Type: application/x-www-form-urlencoded (per OAuth spec)
   */
  @Post('token')
  @Public()
  @HttpCode(HttpStatus.OK)
  async token(
    @Body('grant_type') grantType: string,
    @Body('code') code: string,
    @Body('redirect_uri') redirectUri: string,
    @Body('client_id') bodyClientId: string,
    @Body('client_secret') bodyClientSecret: string,
    @Body('code_verifier') codeVerifier: string,
    @Body('refresh_token') refreshToken: string,
    @Body('scope') scope: string,
    @Headers('authorization') authHeader: string,
  ): Promise<TokenResponse | { error: string; error_description: string }> {
    // Extract client credentials from Basic auth header or body
    let clientId = bodyClientId;
    let clientSecret = bodyClientSecret;

    if (authHeader?.startsWith('Basic ')) {
      const base64 = authHeader.slice(6);
      const decoded = Buffer.from(base64, 'base64').toString('utf-8');
      const [headerClientId, headerClientSecret] = decoded.split(':');
      clientId = headerClientId;
      clientSecret = headerClientSecret;
    }

    if (!grantType) {
      return {
        error: 'invalid_request',
        error_description: 'grant_type is required',
      };
    }

    switch (grantType) {
      case 'authorization_code':
        return this.oauthTokenService.exchangeCode(
          code,
          redirectUri,
          clientId,
          clientSecret,
          codeVerifier,
        );

      case 'refresh_token':
        return this.oauthTokenService.refreshAccessToken(
          refreshToken,
          clientId,
          clientSecret,
        );

      case 'client_credentials':
        return this.oauthTokenService.clientCredentialsGrant(
          clientId,
          clientSecret,
          scope || '',
        );

      default: {
        // Sanitize grant type to prevent injection
        const sanitizedGrantType = String(grantType)
          .slice(0, 50)
          .replace(/[<>'"]/g, '');
        return {
          error: 'unsupported_grant_type',
          error_description: `Grant type '${sanitizedGrantType}' is not supported`,
        };
      }
    }
  }

  /**
   * Token revocation endpoint
   * POST /oauth/revoke
   * Per RFC 7009 - always returns 200
   */
  @Post('revoke')
  @Public()
  @HttpCode(HttpStatus.OK)
  async revoke(
    @Body('token') token: string,
    @Body('token_type_hint') tokenTypeHint: string,
  ) {
    await this.oauthTokenService.revokeToken(token, tokenTypeHint);
    return {}; // RFC 7009 says empty response on success
  }

  /**
   * Token introspection endpoint
   * POST /oauth/introspect
   * Per RFC 7662
   */
  @Post('introspect')
  @Public()
  @HttpCode(HttpStatus.OK)
  async introspect(
    @Body('token') token: string,
    @Body('client_id') bodyClientId: string,
    @Body('client_secret') bodyClientSecret: string,
    @Headers('authorization') authHeader: string,
  ) {
    // Extract client credentials
    let clientId = bodyClientId;
    let clientSecret = bodyClientSecret;

    if (authHeader?.startsWith('Basic ')) {
      const base64 = authHeader.slice(6);
      const decoded = Buffer.from(base64, 'base64').toString('utf-8');
      const [headerClientId, headerClientSecret] = decoded.split(':');
      clientId = headerClientId;
      clientSecret = headerClientSecret;
    }

    return this.oauthTokenService.introspectToken(
      token,
      clientId,
      clientSecret,
    );
  }
}
