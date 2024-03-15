import {
  Controller,
  Get,
  Post,
  Param,
  Query,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AdminService } from './admin.service.js';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard.js';
import { RolesGuard } from '../../common/guards/roles.guard.js';
import { Roles } from '../../common/decorators/roles.decorator.js';
import { CurrentUser } from '../../common/decorators/current-user.decorator.js';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiQuery,
  ApiResponse,
} from '@nestjs/swagger';

interface RequestUser {
  userId: string;
  tenantId: string;
  roles: string[];
}

// TODO: Add rate limiting on admin endpoints to prevent abuse
// Consider using @nestjs/throttler with stricter limits for admin routes

/**
 * Admin Controller
 * Admin dashboard and management endpoints
 */
@Controller('admin')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('tenant_admin', 'super_admin')
@ApiTags('Admin')
@ApiBearerAuth()
export class AdminController {
  constructor(private adminService: AdminService) {}

  // ============== Dashboard ==============

  @Get('dashboard/stats')
  @ApiOperation({ summary: 'Get dashboard statistics' })
  @ApiResponse({ status: 200, description: 'Returns dashboard stats' })
  async getDashboardStats(@CurrentUser() user: RequestUser) {
    return this.adminService.getDashboardStats(user.tenantId);
  }

  // ============== User Management ==============

  @Get('users')
  @ApiOperation({ summary: 'List all users with filtering and pagination' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'search', required: false, type: String })
  @ApiQuery({ name: 'isActive', required: false, type: Boolean })
  @ApiResponse({ status: 200, description: 'Returns paginated users' })
  async listUsers(
    @CurrentUser() user: RequestUser,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
    @Query('search') search?: string,
    @Query('isActive') isActive?: string,
  ) {
    return this.adminService.listUsers(
      user.tenantId,
      page ? parseInt(page, 10) : 1,
      limit ? parseInt(limit, 10) : 20,
      search,
      isActive ? isActive === 'true' : undefined,
    );
  }

  @Get('users/:id')
  @ApiOperation({
    summary: 'Get user details including roles, sessions, activity',
  })
  @ApiResponse({ status: 200, description: 'Returns user details' })
  async getUserDetails(
    @CurrentUser() user: RequestUser,
    @Param('id') id: string,
  ) {
    return this.adminService.getUserDetails(user.tenantId, id);
  }

  @Post('users/:id/deactivate')
  @ApiOperation({ summary: 'Deactivate user and revoke all sessions' })
  @ApiResponse({ status: 200, description: 'User deactivated' })
  async deactivateUser(
    @CurrentUser() user: RequestUser,
    @Param('id') id: string,
  ) {
    await this.adminService.deactivateUser(user.tenantId, id);
    return { message: 'User deactivated' };
  }

  @Post('users/:id/activate')
  @ApiOperation({ summary: 'Activate user' })
  @ApiResponse({ status: 200, description: 'User activated' })
  async activateUser(
    @CurrentUser() user: RequestUser,
    @Param('id') id: string,
  ) {
    await this.adminService.activateUser(user.tenantId, id);
    return { message: 'User activated' };
  }

  @Post('users/:id/force-logout')
  @ApiOperation({ summary: 'Force logout user (revoke all sessions)' })
  @ApiResponse({
    status: 200,
    description: 'Returns count of revoked sessions',
  })
  async forceLogout(@CurrentUser() user: RequestUser, @Param('id') id: string) {
    const count = await this.adminService.forceLogout(user.tenantId, id);
    return { revokedSessions: count };
  }

  // ============== Security ==============

  @Get('security/overview')
  @ApiOperation({ summary: 'Get security overview with suspicious activity' })
  @ApiResponse({ status: 200, description: 'Returns security overview' })
  async getSecurityOverview(@CurrentUser() user: RequestUser) {
    return this.adminService.getSecurityOverview(user.tenantId);
  }

  @Get('security/sessions')
  @ApiOperation({ summary: 'List all active sessions in tenant' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiResponse({ status: 200, description: 'Returns paginated sessions' })
  async listActiveSessions(
    @CurrentUser() user: RequestUser,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    return this.adminService.listActiveSessions(
      user.tenantId,
      page ? parseInt(page, 10) : 1,
      limit ? parseInt(limit, 10) : 50,
    );
  }

  @Post('security/sessions/revoke')
  @ApiOperation({ summary: 'Bulk revoke sessions' })
  @ApiResponse({
    status: 200,
    description: 'Returns count of revoked sessions',
  })
  @HttpCode(HttpStatus.OK)
  async bulkRevokeSessions(@Body('sessionIds') sessionIds: string[]) {
    const count = await this.adminService.bulkRevokeSessions(sessionIds);
    return { revokedCount: count };
  }
}
