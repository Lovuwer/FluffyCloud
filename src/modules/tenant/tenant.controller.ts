import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { TenantService } from './tenant.service.js';
import {
  CreateTenantDto,
  UpdateTenantDto,
  UpdateTenantSettingsDto,
} from './dto/index.js';
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
 * Tenant Controller
 * Manages tenant CRUD operations
 */
@Controller('tenants')
@UseGuards(JwtAuthGuard, RolesGuard)
export class TenantController {
  constructor(private tenantService: TenantService) {}

  @Post()
  @Roles('super_admin')
  @HttpCode(HttpStatus.CREATED)
  async createTenant(@Body() dto: CreateTenantDto) {
    return this.tenantService.createTenant(dto);
  }

  @Get()
  @Roles('super_admin')
  async listTenants() {
    return this.tenantService.listTenants();
  }

  @Get(':id')
  @Roles('tenant_admin', 'super_admin')
  async getTenant(@Param('id') id: string, @CurrentUser() user: RequestUser) {
    // Tenant admins can only view their own tenant
    if (!user.roles.includes('super_admin') && id !== user.tenantId) {
      return this.tenantService.getTenant(user.tenantId);
    }
    return this.tenantService.getTenant(id);
  }

  @Patch(':id')
  @Roles('tenant_admin', 'super_admin')
  async updateTenant(
    @Param('id') id: string,
    @Body() dto: UpdateTenantDto,
    @CurrentUser() user: RequestUser,
  ) {
    // Tenant admins can only update their own tenant
    const tenantId = user.roles.includes('super_admin') ? id : user.tenantId;
    return this.tenantService.updateTenant(tenantId, dto);
  }

  @Delete(':id')
  @Roles('super_admin')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deactivateTenant(@Param('id') id: string) {
    await this.tenantService.deactivateTenant(id);
  }

  @Get(':id/settings')
  @Roles('tenant_admin', 'super_admin')
  async getTenantSettings(
    @Param('id') id: string,
    @CurrentUser() user: RequestUser,
  ) {
    const tenantId = user.roles.includes('super_admin') ? id : user.tenantId;
    return this.tenantService.getTenantSettings(tenantId);
  }

  @Patch(':id/settings')
  @Roles('tenant_admin', 'super_admin')
  async updateTenantSettings(
    @Param('id') id: string,
    @Body() dto: UpdateTenantSettingsDto,
    @CurrentUser() user: RequestUser,
  ) {
    const tenantId = user.roles.includes('super_admin') ? id : user.tenantId;
    return this.tenantService.updateTenantSettings(tenantId, dto);
  }
}
