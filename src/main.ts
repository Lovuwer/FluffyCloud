import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import helmet from 'helmet';
import compression from 'compression';
import { AppModule } from './app.module.js';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Security headers
  app.use(helmet());

  // Compression
  app.use(compression());

  // Global validation pipe for DTOs
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Swagger/OpenAPI configuration
  const config = new DocumentBuilder()
    .setTitle('IAM Platform API')
    .setDescription(
      `Identity and Access Management API

## Getting Started

This API provides comprehensive identity and access management capabilities including:
- **Authentication**: User registration, login, JWT tokens
- **OAuth2 Provider**: Authorization code flow with PKCE, client credentials
- **SAML 2.0**: Service provider for enterprise SSO
- **RBAC**: Fine-grained role-based access control
- **Multi-tenancy**: Full tenant isolation

## Authentication

Most endpoints require authentication via Bearer token. Obtain a token by:
1. Registering a new user at \`POST /auth/register\`
2. Logging in at \`POST /auth/login\`
3. Include the access token in the Authorization header: \`Bearer <token>\`
`,
    )
    .setVersion('1.0')
    .addBearerAuth()
    .addApiKey(
      { type: 'apiKey', name: 'X-Tenant-ID', in: 'header' },
      'tenant-id',
    )
    .addTag('Auth', 'Authentication endpoints')
    .addTag('Sessions', 'Session management')
    .addTag('OAuth Clients', 'OAuth2 client management')
    .addTag('OAuth', 'OAuth2 authorization and token endpoints')
    .addTag('SAML', 'SAML 2.0 service provider')
    .addTag('RBAC', 'Roles and permissions management')
    .addTag('Tenants', 'Tenant management')
    .addTag('Audit Logs', 'Audit logging and compliance')
    .addTag('Admin', 'Administrative operations')
    .addTag('Demo - Tasks', 'Demo task management API')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
  });

  const port = process.env.PORT ?? 3000;
  await app.listen(port);
  console.log(`🚀 Application is running on: http://localhost:${port}`);
  console.log(
    `📚 API documentation available at: http://localhost:${port}/api-docs`,
  );
}
void bootstrap();
