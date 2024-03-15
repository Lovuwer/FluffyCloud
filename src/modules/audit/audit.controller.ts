import { Controller, Get, Query, UseGuards, Res } from '@nestjs/common';
import type { Response } from 'express';
import { AuditService } from './audit.service.js';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard.js';
import { RolesGuard } from '../../common/guards/roles.guard.js';
import { Permissions } from '../../common/decorators/permissions.decorator.js';
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

/**
 * Audit Log Controller
 * Access audit logs with filtering and export
 */
@Controller('audit-logs')
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiTags('Audit Logs')
@ApiBearerAuth()
export class AuditController {
  constructor(private auditService: AuditService) {}

  @Get()
  @Permissions('audit_logs:read', 'audit_logs:list')
  @ApiOperation({ summary: 'List audit logs with filtering' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'actorId', required: false, type: String })
  @ApiQuery({ name: 'action', required: false, type: String })
  @ApiQuery({ name: 'resourceType', required: false, type: String })
  @ApiQuery({ name: 'resourceId', required: false, type: String })
  @ApiQuery({
    name: 'status',
    required: false,
    enum: ['success', 'failure', 'error'],
  })
  @ApiQuery({ name: 'dateFrom', required: false, type: String })
  @ApiQuery({ name: 'dateTo', required: false, type: String })
  @ApiResponse({ status: 200, description: 'Returns paginated audit logs' })
  async listLogs(
    @CurrentUser() user: RequestUser,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
    @Query('actorId') actorId?: string,
    @Query('action') action?: string,
    @Query('resourceType') resourceType?: string,
    @Query('resourceId') resourceId?: string,
    @Query('status') status?: 'success' | 'failure' | 'error',
    @Query('dateFrom') dateFrom?: string,
    @Query('dateTo') dateTo?: string,
  ) {
    return this.auditService.getLogs(
      user.tenantId,
      {
        actorId,
        action,
        resourceType,
        resourceId,
        status,
        dateFrom: dateFrom ? new Date(dateFrom) : undefined,
        dateTo: dateTo ? new Date(dateTo) : undefined,
      },
      {
        page: page ? parseInt(page, 10) : 1,
        limit: limit ? parseInt(limit, 10) : 50,
      },
    );
  }

  @Get('export')
  @Permissions('audit_logs:read')
  @ApiOperation({ summary: 'Export audit logs' })
  @ApiQuery({ name: 'format', required: false, enum: ['json', 'csv'] })
  @ApiResponse({ status: 200, description: 'Returns exported audit logs' })
  async exportLogs(
    @CurrentUser() user: RequestUser,
    @Query('format') format: 'json' | 'csv' = 'json',
    @Query('actorId') actorId?: string,
    @Query('action') action?: string,
    @Query('resourceType') resourceType?: string,
    @Query('dateFrom') dateFrom?: string,
    @Query('dateTo') dateTo?: string,
    @Res() res?: Response,
  ) {
    const exported = await this.auditService.exportLogs(
      user.tenantId,
      {
        actorId,
        action,
        resourceType,
        dateFrom: dateFrom ? new Date(dateFrom) : undefined,
        dateTo: dateTo ? new Date(dateTo) : undefined,
      },
      format,
    );

    if (res) {
      const contentType = format === 'csv' ? 'text/csv' : 'application/json';
      const filename = `audit-logs-${new Date().toISOString().split('T')[0]}.${format}`;

      res.setHeader('Content-Type', contentType);
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${filename}"`,
      );
      return res.send(exported);
    }

    return exported;
  }

  @Get('summary')
  @Permissions('audit_logs:read')
  @ApiOperation({ summary: 'Get audit log summary statistics' })
  @ApiResponse({ status: 200, description: 'Returns audit log statistics' })
  async getSummary(@CurrentUser() user: RequestUser) {
    const now = new Date();
    const todayStart = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate(),
    );
    const weekStart = new Date(todayStart.getTime() - 7 * 24 * 60 * 60 * 1000);

    const [todayLogs, weekLogs, failedLogins] = await Promise.all([
      this.auditService.getLogs(
        user.tenantId,
        { dateFrom: todayStart },
        { limit: 1 },
      ),
      this.auditService.getLogs(
        user.tenantId,
        { dateFrom: weekStart },
        { limit: 1 },
      ),
      this.auditService.getLogs(
        user.tenantId,
        { action: 'user.login_failed', dateFrom: todayStart },
        { limit: 1 },
      ),
    ]);

    return {
      eventsToday: todayLogs.meta.total,
      eventsThisWeek: weekLogs.meta.total,
      failedLoginsToday: failedLogins.meta.total,
    };
  }
}
