import { Module } from '@nestjs/common';
import { SamlController } from './saml.controller.js';
import { SamlService } from './services/saml.service.js';
import { SamlConfigService } from './services/saml-config.service.js';
import { AuthModule } from '../auth/auth.module.js';

@Module({
  imports: [AuthModule],
  controllers: [SamlController],
  providers: [SamlService, SamlConfigService],
  exports: [SamlService, SamlConfigService],
})
export class SamlModule {}
