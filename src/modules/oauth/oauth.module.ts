import { Module } from '@nestjs/common';
import { OAuthClientController } from './oauth-client.controller.js';
import { OAuthController } from './oauth.controller.js';
import { OAuthClientService } from './services/oauth-client.service.js';
import { AuthorizationService } from './services/authorization.service.js';
import { OAuthTokenService } from './services/oauth-token.service.js';
import { AuthModule } from '../auth/auth.module.js';

@Module({
  imports: [AuthModule],
  controllers: [OAuthClientController, OAuthController],
  providers: [OAuthClientService, AuthorizationService, OAuthTokenService],
  exports: [OAuthClientService, AuthorizationService, OAuthTokenService],
})
export class OAuthModule {}
