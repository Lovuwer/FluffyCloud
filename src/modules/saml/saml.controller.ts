import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Res,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import type { Response } from 'express';
import crypto from 'crypto';
import { SamlService } from './services/saml.service.js';
import { SamlConfigService } from './services/saml-config.service.js';
import { CreateSamlIdpDto, UpdateSamlIdpDto } from './dto/index.js';
import { PrismaService } from '../../database/prisma.service.js';
import { TokenService } from '../auth/services/token.service.js';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard.js';
import { RolesGuard } from '../../common/guards/roles.guard.js';
import { Roles } from '../../common/decorators/roles.decorator.js';
import { CurrentUser } from '../../common/decorators/current-user.decorator.js';
import { Public } from '../../common/decorators/public.decorator.js';

interface RequestUser {
  userId: string;
  tenantId: string;
  roles: string[];
}

/**
 * SAML Controller
 * Handles SAML SSO flow and IdP management
 */
@Controller('saml')
export class SamlController {
  constructor(
    private samlService: SamlService,
    private samlConfigService: SamlConfigService,
    private prisma: PrismaService,
    private tokenService: TokenService,
  ) {}

  // ============== SAML SSO Endpoints ==============

  /**
   * SP Metadata endpoint
   * GET /saml/metadata/:tenantSlug
   */
  @Get('metadata/:tenantSlug')
  @Public()
  getMetadata(@Param('tenantSlug') tenantSlug: string, @Res() res: Response) {
    const metadata = this.samlConfigService.generateMetadataXml(tenantSlug);
    res.setHeader('Content-Type', 'application/xml');
    return res.send(metadata);
  }

  /**
   * Initiate SAML login
   * GET /saml/login/:tenantSlug
   */
  @Get('login/:tenantSlug')
  @Public()
  async initiateLogin(
    @Param('tenantSlug') tenantSlug: string,
    @Res() res: Response,
  ) {
    try {
      // Get tenant
      const tenant = await this.prisma.tenant.findUnique({
        where: { slug: tenantSlug },
      });

      if (!tenant) {
        return res.status(404).send('Tenant not found');
      }

      // Get IdP for tenant
      const idp = await this.samlService.getIdPForTenant(tenant.id);

      // Generate SAML AuthnRequest
      // For simplicity, we'll redirect to IdP with basic params
      // In production, use passport-saml to generate proper signed request
      const spEntityId = this.samlConfigService.getEntityId(tenantSlug);
      const acsUrl = this.samlConfigService.getAcsUrl(tenantSlug);

      console.log(
        `[SAML] Initiating login for tenant ${tenantSlug} to IdP ${idp.entityId}`,
      );

      // Generate cryptographically secure ID for SAML request
      const requestId = `_${crypto.randomBytes(16).toString('hex')}`;

      // Simple redirect (in production, use proper SAML request with passport-saml)
      // WARNING: This is a simplified implementation - production should use proper SAML library
      const samlRequest = Buffer.from(
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
          ID="${requestId}"
          Version="2.0"
          IssueInstant="${new Date().toISOString()}"
          Destination="${idp.ssoUrl}"
          AssertionConsumerServiceURL="${acsUrl}">
          <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${spEntityId}</saml:Issuer>
        </samlp:AuthnRequest>`,
      ).toString('base64');

      const redirectUrl = `${idp.ssoUrl}?SAMLRequest=${encodeURIComponent(samlRequest)}`;
      return res.redirect(redirectUrl);
    } catch (error) {
      console.error('[SAML] Login initiation error:', error);
      return res.status(500).send('SAML login failed');
    }
  }

  /**
   * Assertion Consumer Service (ACS)
   * POST /saml/acs/:tenantSlug
   */
  @Post('acs/:tenantSlug')
  @Public()
  async assertionConsumerService(
    @Param('tenantSlug') tenantSlug: string,
    @Body('SAMLResponse') samlResponse: string,
    @Res() res: Response,
  ) {
    try {
      // Get tenant
      const tenant = await this.prisma.tenant.findUnique({
        where: { slug: tenantSlug },
      });

      if (!tenant) {
        return res.status(404).send('Tenant not found');
      }

      // Get IdP
      const idp = await this.samlService.getIdPForTenant(tenant.id);

      // Decode and parse SAML response
      // SECURITY WARNING: This is a simplified implementation for development purposes.
      // In production, you MUST use passport-saml to properly validate XML signatures
      // to prevent forgery attacks. The signature validation is critical for security.
      // TODO: Implement proper SAML signature validation using passport-saml
      const decodedResponse = Buffer.from(samlResponse, 'base64').toString(
        'utf-8',
      );
      console.log('[SAML] Received SAML response for tenant:', tenantSlug);

      // Extract NameID and attributes (simplified - use proper SAML parser in production)
      const nameIdMatch = decodedResponse.match(
        /<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/,
      );
      const nameId = nameIdMatch ? nameIdMatch[1] : null;

      if (!nameId) {
        console.error('[SAML] No NameID found in response');
        return res.status(400).send('Invalid SAML response: No NameID');
      }

      // Extract attributes (simplified)
      const attributes: Record<string, string> = {};
      const attrMatches = decodedResponse.matchAll(
        /<saml:Attribute[^>]*Name="([^"]+)"[^>]*>.*?<saml:AttributeValue[^>]*>([^<]+)<\/saml:AttributeValue>/gs,
      );
      for (const match of attrMatches) {
        attributes[match[1]] = match[2];
      }

      console.log('[SAML] User NameID:', nameId);
      console.log('[SAML] Attributes:', attributes);

      // Find or create user
      const attributeMapping = (idp.attributeMapping || {}) as Record<
        string,
        string
      >;
      const user = await this.samlService.findOrCreateUserFromSaml(
        tenant.id,
        idp.id,
        nameId,
        attributes,
        attributeMapping,
      );

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

      // Generate JWT tokens
      const accessToken = this.tokenService.generateAccessToken(
        { id: user.id, email: user.email },
        tenant.id,
        roles,
        permissions,
      );

      const refreshToken = await this.tokenService.generateRefreshToken(
        user.id,
        tenant.id,
      );

      // Update last login
      await this.prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      });

      console.log(`[SAML] User ${user.email} authenticated successfully`);

      // Redirect to frontend with tokens
      // In production, use a more secure method (e.g., POST to frontend, use cookies)
      const frontendUrl = `/auth/callback?token=${accessToken}&refresh=${refreshToken}`;
      return res.redirect(frontendUrl);
    } catch (error) {
      console.error('[SAML] ACS error:', error);
      return res.status(500).send('SAML authentication failed');
    }
  }

  /**
   * Single Logout endpoint
   * GET /saml/slo/:tenantSlug
   */
  @Get('slo/:tenantSlug')
  @Public()
  singleLogout(@Param('tenantSlug') tenantSlug: string, @Res() res: Response) {
    // TODO: Implement proper SLO
    console.log(`[SAML] Single logout requested for tenant: ${tenantSlug}`);
    return res.redirect('/');
  }

  // ============== IdP Management Endpoints ==============

  @Post('idp')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('tenant_admin', 'super_admin')
  @HttpCode(HttpStatus.CREATED)
  async createIdP(
    @Body() dto: CreateSamlIdpDto,
    @CurrentUser() user: RequestUser,
  ) {
    return this.samlService.createIdPConfig(user.tenantId, dto);
  }

  @Get('idp')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('tenant_admin', 'super_admin')
  async listIdPs(@CurrentUser() user: RequestUser) {
    return this.samlService.listIdPs(user.tenantId);
  }

  @Get('idp/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('tenant_admin', 'super_admin')
  async getIdP(@Param('id') id: string) {
    return this.samlService.getIdPById(id);
  }

  @Patch('idp/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('tenant_admin', 'super_admin')
  async updateIdP(@Param('id') id: string, @Body() dto: UpdateSamlIdpDto) {
    return this.samlService.updateIdPConfig(id, dto);
  }

  @Delete('idp/:id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('tenant_admin', 'super_admin')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteIdP(@Param('id') id: string) {
    await this.samlService.deleteIdP(id);
  }
}
