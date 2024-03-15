import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../../../database/prisma.service.js';
import { CreateSamlIdpDto, UpdateSamlIdpDto } from '../dto/saml-idp.dto.js';

interface AttributeMapping {
  email?: string;
  firstName?: string;
  lastName?: string;
  groups?: string;
  [key: string]: string | undefined;
}

interface SamlAttributes {
  [key: string]: string | string[] | undefined;
}

/**
 * SAML Service
 * Manages SAML IdP configurations and user provisioning
 */
@Injectable()
export class SamlService {
  constructor(private prisma: PrismaService) {}

  /**
   * Create IdP configuration for a tenant
   */
  async createIdPConfig(tenantId: string, dto: CreateSamlIdpDto) {
    // Validate certificate format (basic check)
    if (!dto.certificate.includes('-----BEGIN CERTIFICATE-----')) {
      throw new ConflictException(
        'Invalid certificate format. Expected PEM format.',
      );
    }

    const idp = await this.prisma.samlIdentityProvider.create({
      data: {
        tenantId,
        name: dto.name,
        entityId: dto.entityId,
        ssoUrl: dto.ssoUrl,
        sloUrl: dto.sloUrl,
        certificate: dto.certificate,
        nameIdFormat:
          dto.nameIdFormat ||
          'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        attributeMapping: dto.attributeMapping || {},
        isActive: true,
      },
    });

    console.log(`[AUDIT] SAML IdP created: ${idp.name} for tenant ${tenantId}`);

    return this.formatIdpResponse(idp);
  }

  /**
   * Update IdP configuration
   */
  async updateIdPConfig(id: string, dto: UpdateSamlIdpDto) {
    const existing = await this.prisma.samlIdentityProvider.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException('IdP configuration not found');
    }

    if (
      dto.certificate &&
      !dto.certificate.includes('-----BEGIN CERTIFICATE-----')
    ) {
      throw new ConflictException(
        'Invalid certificate format. Expected PEM format.',
      );
    }

    const idp = await this.prisma.samlIdentityProvider.update({
      where: { id },
      data: {
        name: dto.name,
        entityId: dto.entityId,
        ssoUrl: dto.ssoUrl,
        sloUrl: dto.sloUrl,
        certificate: dto.certificate,
        nameIdFormat: dto.nameIdFormat,
        attributeMapping: dto.attributeMapping,
        isActive: dto.isActive,
      },
    });

    console.log(`[AUDIT] SAML IdP updated: ${id}`);

    return this.formatIdpResponse(idp);
  }

  /**
   * Get IdP by ID
   */
  async getIdPById(id: string) {
    const idp = await this.prisma.samlIdentityProvider.findUnique({
      where: { id },
    });

    if (!idp) {
      throw new NotFoundException('IdP configuration not found');
    }

    return this.formatIdpResponse(idp);
  }

  /**
   * Get active IdP for a tenant
   */
  async getIdPForTenant(tenantId: string) {
    const idp = await this.prisma.samlIdentityProvider.findFirst({
      where: { tenantId, isActive: true },
    });

    if (!idp) {
      throw new NotFoundException('No active IdP configured for this tenant');
    }

    return idp;
  }

  /**
   * List IdPs for a tenant
   */
  async listIdPs(tenantId: string) {
    const idps = await this.prisma.samlIdentityProvider.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' },
    });

    return idps.map((idp) => this.formatIdpResponse(idp));
  }

  /**
   * Delete IdP configuration
   */
  async deleteIdP(id: string) {
    const existing = await this.prisma.samlIdentityProvider.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException('IdP configuration not found');
    }

    await this.prisma.samlIdentityProvider.delete({
      where: { id },
    });

    console.log(`[AUDIT] SAML IdP deleted: ${id}`);
  }

  /**
   * Find or create user from SAML assertion (JIT provisioning)
   */
  async findOrCreateUserFromSaml(
    tenantId: string,
    idpId: string,
    nameId: string,
    attributes: SamlAttributes,
    attributeMapping: AttributeMapping,
  ) {
    // Look for existing link
    const existingLink = await this.prisma.samlUserLink.findUnique({
      where: {
        idpId_nameId: {
          idpId,
          nameId,
        },
      },
      include: {
        user: true,
      },
    });

    if (existingLink) {
      // Update cached attributes
      await this.prisma.samlUserLink.update({
        where: { id: existingLink.id },
        data: { attributes: attributes as object },
      });

      console.log(`[SAML] Existing user logged in: ${existingLink.user.email}`);
      return existingLink.user;
    }

    // JIT provision new user
    const email = this.extractAttribute(
      attributes,
      attributeMapping.email || 'email',
    );
    const firstName =
      this.extractAttribute(
        attributes,
        attributeMapping.firstName || 'firstName',
      ) || 'Unknown';
    const lastName =
      this.extractAttribute(
        attributes,
        attributeMapping.lastName || 'lastName',
      ) || 'User';

    if (!email) {
      throw new ConflictException('Email attribute not found in SAML response');
    }

    // Check if user with this email already exists
    const existingUser = await this.prisma.user.findUnique({
      where: {
        tenantId_email: {
          tenantId,
          email,
        },
      },
    });

    if (existingUser) {
      // Link existing user to SAML
      await this.prisma.samlUserLink.create({
        data: {
          userId: existingUser.id,
          idpId,
          nameId,
          attributes: attributes as object,
        },
      });

      console.log(`[SAML] Existing user linked to SAML: ${email}`);
      return existingUser;
    }

    // Create new user
    const user = await this.prisma.$transaction(async (tx) => {
      const newUser = await tx.user.create({
        data: {
          tenantId,
          email,
          firstName,
          lastName,
          passwordHash: null, // SAML users don't have passwords
          emailVerified: true, // Trust IdP's verification
          isActive: true,
        },
      });

      // Create SAML link
      await tx.samlUserLink.create({
        data: {
          userId: newUser.id,
          idpId,
          nameId,
          attributes: attributes as object,
        },
      });

      // Assign default role
      const userRole = await tx.role.findFirst({
        where: { tenantId, name: 'user' },
      });

      if (userRole) {
        await tx.userRole.create({
          data: {
            userId: newUser.id,
            roleId: userRole.id,
            tenantId,
          },
        });
      }

      return newUser;
    });

    console.log(`[SAML] New user provisioned: ${email}`);

    // TODO: Map IdP groups to roles if configured
    const groups = this.extractAttribute(
      attributes,
      attributeMapping.groups || 'groups',
    );
    if (groups) {
      console.log(`[SAML] User groups: ${groups} (TODO: map to roles)`);
    }

    return user;
  }

  /**
   * Extract attribute value from SAML attributes
   */
  private extractAttribute(
    attributes: SamlAttributes,
    key: string,
  ): string | undefined {
    const value = attributes[key];
    if (Array.isArray(value)) {
      return value[0];
    }
    return value;
  }

  private formatIdpResponse(idp: {
    id: string;
    name: string;
    entityId: string;
    ssoUrl: string;
    sloUrl: string | null;
    nameIdFormat: string;
    attributeMapping: unknown;
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
  }) {
    return {
      id: idp.id,
      name: idp.name,
      entityId: idp.entityId,
      ssoUrl: idp.ssoUrl,
      sloUrl: idp.sloUrl,
      nameIdFormat: idp.nameIdFormat,
      attributeMapping: idp.attributeMapping,
      isActive: idp.isActive,
      createdAt: idp.createdAt,
      updatedAt: idp.updatedAt,
    };
  }
}
