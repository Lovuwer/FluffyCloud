import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service.js';
import { AuditAction, ActorType, AuditStatus } from './audit-actions.js';

interface LogParams {
  tenantId: string;
  actorId?: string;
  actorType?: ActorType;
  action: AuditAction | string;
  resourceType: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  status?: AuditStatus;
  errorMessage?: string;
}

interface AuditLogFilters {
  actorId?: string;
  action?: string;
  resourceType?: string;
  resourceId?: string;
  status?: AuditStatus;
  dateFrom?: Date;
  dateTo?: Date;
  search?: string;
}

interface PaginationParams {
  page?: number;
  limit?: number;
}

/**
 * Audit Service
 * Handles audit logging for security and compliance
 * Log method is non-blocking and never throws
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private prisma: PrismaService) {}

  /**
   * Log an audit event
   * Non-blocking - uses fire-and-forget pattern
   */
  async log(params: LogParams): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data: {
          tenantId: params.tenantId,
          actorId: params.actorId,
          actorType: params.actorType || 'user',
          action: params.action,
          resourceType: params.resourceType,
          resourceId: params.resourceId,
          details: params.details as object,
          ipAddress: params.ipAddress,
          userAgent: params.userAgent,
          status: params.status || 'success',
          errorMessage: params.errorMessage,
        },
      });
    } catch (error) {
      // Audit logging should never throw - just warn
      this.logger.warn(
        'Failed to create audit log',
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  /**
   * Log authentication action
   */
  async logAuth(
    action: AuditAction,
    tenantId: string,
    userId: string | null,
    status: AuditStatus,
    details?: Record<string, unknown>,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      tenantId,
      actorId: userId || undefined,
      actorType: 'user',
      action,
      resourceType: 'auth',
      resourceId: userId || undefined,
      details: this.redactSensitive(details),
      status,
      ipAddress,
      userAgent,
    });
  }

  /**
   * Log user action
   */
  async logUserAction(
    action: AuditAction,
    tenantId: string,
    actorId: string,
    targetUserId: string,
    details?: Record<string, unknown>,
  ): Promise<void> {
    await this.log({
      tenantId,
      actorId,
      actorType: 'user',
      action,
      resourceType: 'user',
      resourceId: targetUserId,
      details: this.redactSensitive(details),
      status: 'success',
    });
  }

  /**
   * Log OAuth action
   */
  async logOAuthAction(
    action: AuditAction,
    tenantId: string,
    actorId: string | undefined,
    clientId: string,
    details?: Record<string, unknown>,
  ): Promise<void> {
    await this.log({
      tenantId,
      actorId,
      actorType: actorId ? 'user' : 'oauth_client',
      action,
      resourceType: 'oauth_client',
      resourceId: clientId,
      details: this.redactSensitive(details),
      status: 'success',
    });
  }

  /**
   * Log session action
   */
  async logSessionAction(
    action: AuditAction,
    tenantId: string,
    userId: string,
    sessionId: string,
    details?: Record<string, unknown>,
  ): Promise<void> {
    await this.log({
      tenantId,
      actorId: userId,
      actorType: 'user',
      action,
      resourceType: 'session',
      resourceId: sessionId,
      details,
      status: 'success',
    });
  }

  /**
   * Get audit logs with filters and pagination
   */
  async getLogs(
    tenantId: string,
    filters: AuditLogFilters = {},
    pagination: PaginationParams = {},
  ) {
    const { page = 1, limit = 50 } = pagination;
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = {
      tenantId,
    };

    if (filters.actorId) {
      where.actorId = filters.actorId;
    }

    if (filters.action) {
      // Support prefix matching like 'user.*'
      if (filters.action.endsWith('*')) {
        const prefix = filters.action.slice(0, -1);
        where.action = { startsWith: prefix };
      } else {
        where.action = filters.action;
      }
    }

    if (filters.resourceType) {
      where.resourceType = filters.resourceType;
    }

    if (filters.resourceId) {
      where.resourceId = filters.resourceId;
    }

    if (filters.status) {
      where.status = filters.status;
    }

    if (filters.dateFrom || filters.dateTo) {
      where.createdAt = {};
      if (filters.dateFrom) {
        (where.createdAt as Record<string, unknown>).gte = filters.dateFrom;
      }
      if (filters.dateTo) {
        (where.createdAt as Record<string, unknown>).lte = filters.dateTo;
      }
    }

    const [logs, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        include: {
          actor: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true,
            },
          },
        },
      }),
      this.prisma.auditLog.count({ where }),
    ]);

    return {
      data: logs,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Get user activity history
   */
  async getUserActivity(
    userId: string,
    tenantId: string,
    dateFrom?: Date,
    dateTo?: Date,
  ) {
    return this.getLogs(
      tenantId,
      {
        actorId: userId,
        dateFrom,
        dateTo,
      },
      { limit: 100 },
    );
  }

  /**
   * Get resource history
   */
  async getResourceHistory(
    resourceType: string,
    resourceId: string,
    tenantId: string,
  ) {
    return this.getLogs(tenantId, { resourceType, resourceId }, { limit: 100 });
  }

  /**
   * Export logs as JSON or CSV
   */
  async exportLogs(
    tenantId: string,
    filters: AuditLogFilters,
    format: 'json' | 'csv' = 'json',
  ): Promise<string> {
    const { data } = await this.getLogs(tenantId, filters, { limit: 10000 });

    if (format === 'csv') {
      const headers = [
        'id',
        'createdAt',
        'action',
        'actorType',
        'actorId',
        'resourceType',
        'resourceId',
        'status',
        'ipAddress',
      ];
      const rows = data.map((log) =>
        headers
          .map((h) => {
            const value = log[h as keyof typeof log];
            if (value === null || value === undefined) return '';
            if (value instanceof Date) return value.toISOString();
            if (typeof value === 'object') return JSON.stringify(value);
            return String(value).replace(/"/g, '""');
          })
          .map((v) => `"${v}"`)
          .join(','),
      );
      return [headers.join(','), ...rows].join('\n');
    }

    return JSON.stringify(data, null, 2);
  }

  /**
   * Redact sensitive data from details
   */
  private redactSensitive(
    details?: Record<string, unknown>,
  ): Record<string, unknown> | undefined {
    if (!details) return undefined;

    const sensitiveKeys = [
      'password',
      'passwordHash',
      'token',
      'secret',
      'clientSecret',
      'refreshToken',
      'accessToken',
    ];

    const redacted = { ...details };
    for (const key of Object.keys(redacted)) {
      if (
        sensitiveKeys.some((sk) => key.toLowerCase().includes(sk.toLowerCase()))
      ) {
        redacted[key] = '[REDACTED]';
      }
    }

    return redacted;
  }
}
