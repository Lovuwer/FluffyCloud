import {
  Controller,
  Post,
  Get,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { OAuthClientService } from './services/oauth-client.service.js';
import { CreateOAuthClientDto, UpdateOAuthClientDto } from './dto/index.js';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard.js';
import { RolesGuard } from '../../common/guards/roles.guard.js';
import { Roles } from '../../common/decorators/roles.decorator.js';
import { CurrentUser } from '../../common/decorators/current-user.decorator.js';

interface RequestUser {
  userId: string;
  tenantId: string;
  roles: string[];
}

/**
 * OAuth Client Management Controller
 * CRUD endpoints for managing OAuth clients
 * Only tenant admins can manage clients
 */
@Controller('oauth/clients')
@UseGuards(JwtAuthGuard, RolesGuard)
export class OAuthClientController {
  constructor(private readonly oauthClientService: OAuthClientService) {}

  @Post()
  @Roles('tenant_admin', 'super_admin')
  @HttpCode(HttpStatus.CREATED)
  async createClient(
    @Body() dto: CreateOAuthClientDto,
    @CurrentUser() user: RequestUser,
  ) {
    // If not super_admin, force tenantId to user's tenant
    if (!user.roles.includes('super_admin')) {
      dto.tenantId = user.tenantId;
    }
    return this.oauthClientService.createClient(dto);
  }

  @Get()
  @Roles('tenant_admin', 'super_admin')
  async listClients(@CurrentUser() user: RequestUser) {
    // Super admins can see all platform-level clients
    // Tenant admins see their tenant's clients
    const tenantId = user.roles.includes('super_admin')
      ? undefined
      : user.tenantId;
    return this.oauthClientService.listClients(tenantId);
  }

  @Get(':id')
  @Roles('tenant_admin', 'super_admin')
  async getClient(@Param('id') id: string) {
    return this.oauthClientService.getClientById(id);
  }

  @Patch(':id')
  @Roles('tenant_admin', 'super_admin')
  async updateClient(
    @Param('id') id: string,
    @Body() dto: UpdateOAuthClientDto,
  ) {
    return this.oauthClientService.updateClient(id, dto);
  }

  @Post(':id/rotate-secret')
  @Roles('tenant_admin', 'super_admin')
  async rotateSecret(@Param('id') id: string) {
    return this.oauthClientService.rotateClientSecret(id);
  }

  @Delete(':id')
  @Roles('tenant_admin', 'super_admin')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteClient(@Param('id') id: string) {
    await this.oauthClientService.deleteClient(id);
  }
}
