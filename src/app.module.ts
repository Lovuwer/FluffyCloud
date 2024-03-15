import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller.js';
import { AppService } from './app.service.js';
import { DatabaseModule } from './database/database.module.js';
import { RedisModule } from './modules/redis/redis.module.js';
import { AuthModule } from './modules/auth/auth.module.js';
import { OAuthModule } from './modules/oauth/oauth.module.js';
import { SamlModule } from './modules/saml/saml.module.js';
import { RbacModule } from './modules/rbac/rbac.module.js';
import { TenantModule } from './modules/tenant/tenant.module.js';
import { SessionModule } from './modules/session/session.module.js';
import { AuditModule } from './modules/audit/audit.module.js';
import { DemoModule } from './modules/demo/demo.module.js';
import { AdminModule } from './modules/admin/admin.module.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env', '.env.local'],
    }),
    DatabaseModule,
    RedisModule,
    AuthModule,
    OAuthModule,
    SamlModule,
    RbacModule,
    TenantModule,
    SessionModule,
    AuditModule,
    DemoModule,
    AdminModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
