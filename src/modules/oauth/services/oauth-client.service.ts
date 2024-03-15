import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../../../database/prisma.service.js';
import { CreateOAuthClientDto, UpdateOAuthClientDto } from '../dto/index.js';
import crypto from 'crypto';
import bcrypt from 'bcrypt';

/**
 * OAuth Client Service
 * Manages OAuth2 client applications registration and validation
 */
@Injectable()
export class OAuthClientService {
  constructor(private prisma: PrismaService) {}

  /**
   * Generate a random client ID (32 char alphanumeric)
   */
  private generateClientId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Generate a random client secret (64 char alphanumeric)
   */
  private generateClientSecret(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Create a new OAuth client
   * Returns the client with plain text secret (only shown once!)
   */
  async createClient(dto: CreateOAuthClientDto) {
    const clientId = this.generateClientId();
    const clientSecret = this.generateClientSecret();
    const clientSecretHash = await bcrypt.hash(clientSecret, 12);

    // Validate grant types
    const validGrantTypes = [
      'authorization_code',
      'refresh_token',
      'client_credentials',
    ];
    for (const grantType of dto.allowedGrantTypes) {
      if (!validGrantTypes.includes(grantType)) {
        throw new ConflictException(`Invalid grant type: ${grantType}`);
      }
    }

    // TODO: Validate redirect_uris - no localhost in production

    const client = await this.prisma.oAuthClient.create({
      data: {
        clientId,
        clientSecretHash,
        name: dto.name,
        description: dto.description,
        tenantId: dto.tenantId || null,
        redirectUris: dto.redirectUris,
        allowedGrantTypes: dto.allowedGrantTypes,
        allowedScopes: dto.allowedScopes,
        isConfidential: dto.isConfidential ?? true,
        isActive: true,
      },
    });

    // Log client creation for audit
    console.log(`[AUDIT] OAuth client created: ${client.id} (${client.name})`);

    // Return client with plain text secret (only shown once!)
    return {
      id: client.id,
      clientId: client.clientId,
      clientSecret, // Plain text - only returned on creation!
      name: client.name,
      description: client.description,
      tenantId: client.tenantId,
      redirectUris: client.redirectUris,
      allowedGrantTypes: client.allowedGrantTypes,
      allowedScopes: client.allowedScopes,
      isConfidential: client.isConfidential,
      isActive: client.isActive,
      createdAt: client.createdAt,
    };
  }

  /**
   * Validate client credentials
   */
  async validateClient(
    clientId: string,
    clientSecret: string,
  ): Promise<boolean> {
    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId },
    });

    if (!client || !client.isActive) {
      return false;
    }

    return bcrypt.compare(clientSecret, client.clientSecretHash);
  }

  /**
   * Get client by client_id
   */
  async getClientByClientId(clientId: string) {
    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId },
    });

    if (!client) {
      throw new NotFoundException('OAuth client not found');
    }

    // Don't return the secret hash
    return {
      id: client.id,
      clientId: client.clientId,
      name: client.name,
      description: client.description,
      tenantId: client.tenantId,
      redirectUris: client.redirectUris,
      allowedGrantTypes: client.allowedGrantTypes,
      allowedScopes: client.allowedScopes,
      isConfidential: client.isConfidential,
      isActive: client.isActive,
      createdAt: client.createdAt,
      updatedAt: client.updatedAt,
    };
  }

  /**
   * Get client by internal ID
   */
  async getClientById(id: string) {
    const client = await this.prisma.oAuthClient.findUnique({
      where: { id },
    });

    if (!client) {
      throw new NotFoundException('OAuth client not found');
    }

    return {
      id: client.id,
      clientId: client.clientId,
      name: client.name,
      description: client.description,
      tenantId: client.tenantId,
      redirectUris: client.redirectUris,
      allowedGrantTypes: client.allowedGrantTypes,
      allowedScopes: client.allowedScopes,
      isConfidential: client.isConfidential,
      isActive: client.isActive,
      createdAt: client.createdAt,
      updatedAt: client.updatedAt,
    };
  }

  /**
   * Update client settings
   */
  async updateClient(id: string, dto: UpdateOAuthClientDto) {
    const existing = await this.prisma.oAuthClient.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException('OAuth client not found');
    }

    const client = await this.prisma.oAuthClient.update({
      where: { id },
      data: {
        name: dto.name,
        description: dto.description,
        redirectUris: dto.redirectUris,
        allowedGrantTypes: dto.allowedGrantTypes,
        allowedScopes: dto.allowedScopes,
        isConfidential: dto.isConfidential,
        isActive: dto.isActive,
      },
    });

    return {
      id: client.id,
      clientId: client.clientId,
      name: client.name,
      description: client.description,
      tenantId: client.tenantId,
      redirectUris: client.redirectUris,
      allowedGrantTypes: client.allowedGrantTypes,
      allowedScopes: client.allowedScopes,
      isConfidential: client.isConfidential,
      isActive: client.isActive,
      createdAt: client.createdAt,
      updatedAt: client.updatedAt,
    };
  }

  /**
   * Rotate client secret
   * Returns the new secret in plain text (only shown once!)
   */
  async rotateClientSecret(id: string) {
    const existing = await this.prisma.oAuthClient.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException('OAuth client not found');
    }

    const newSecret = this.generateClientSecret();
    const newSecretHash = await bcrypt.hash(newSecret, 12);

    await this.prisma.oAuthClient.update({
      where: { id },
      data: {
        clientSecretHash: newSecretHash,
      },
    });

    // Log secret rotation for audit
    console.log(
      `[AUDIT] OAuth client secret rotated: ${id} (${existing.name})`,
    );

    return {
      clientId: existing.clientId,
      clientSecret: newSecret, // Plain text - only returned on rotation!
    };
  }

  /**
   * List clients for a tenant (or all platform-level clients if tenantId is null)
   */
  async listClients(tenantId?: string) {
    const clients = await this.prisma.oAuthClient.findMany({
      where: tenantId ? { tenantId } : { tenantId: null },
      orderBy: { createdAt: 'desc' },
    });

    return clients.map((client) => ({
      id: client.id,
      clientId: client.clientId,
      name: client.name,
      description: client.description,
      tenantId: client.tenantId,
      redirectUris: client.redirectUris,
      allowedGrantTypes: client.allowedGrantTypes,
      allowedScopes: client.allowedScopes,
      isConfidential: client.isConfidential,
      isActive: client.isActive,
      createdAt: client.createdAt,
      updatedAt: client.updatedAt,
    }));
  }

  /**
   * Soft delete a client (set is_active = false)
   */
  async deleteClient(id: string) {
    const existing = await this.prisma.oAuthClient.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException('OAuth client not found');
    }

    await this.prisma.oAuthClient.update({
      where: { id },
      data: { isActive: false },
    });

    console.log(`[AUDIT] OAuth client deactivated: ${id} (${existing.name})`);
  }

  /**
   * Validate if redirect URI is allowed for client
   */
  isRedirectUriAllowed(
    client: { redirectUris: string[] },
    redirectUri: string,
  ): boolean {
    return client.redirectUris.includes(redirectUri);
  }

  /**
   * Validate if scopes are allowed for client
   */
  areScopesAllowed(
    client: { allowedScopes: string[] },
    scopes: string[],
  ): boolean {
    return scopes.every((scope) => client.allowedScopes.includes(scope));
  }

  /**
   * Validate if grant type is allowed for client
   */
  isGrantTypeAllowed(
    client: { allowedGrantTypes: string[] },
    grantType: string,
  ): boolean {
    return client.allowedGrantTypes.includes(grantType);
  }
}
