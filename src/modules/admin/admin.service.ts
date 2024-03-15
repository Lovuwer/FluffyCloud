import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service.js';

/**
 * Admin Service
 * Dashboard statistics and admin operations
 */
@Injectable()
export class AdminService {
  constructor(private prisma: PrismaService) {}

  /**
   * Get dashboard statistics
   */
  async getDashboardStats(tenantId: string) {
    const now = new Date();
    const todayStart = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate(),
    );
    const weekStart = new Date(todayStart.getTime() - 7 * 24 * 60 * 60 * 1000);

    // User stats
    const [totalUsers, activeUsers, newUsersThisWeek] = await Promise.all([
      this.prisma.user.count({ where: { tenantId } }),
      this.prisma.user.count({ where: { tenantId, isActive: true } }),
      this.prisma.user.count({
        where: {
          tenantId,
          createdAt: { gte: weekStart },
        },
      }),
    ]);

    // Session stats
    const [activeSessions] = await Promise.all([
      this.prisma.session.count({
        where: {
          tenantId,
          revokedAt: null,
          expiresAt: { gt: now },
        },
      }),
    ]);

    // Auth stats (from audit logs)
    const [loginsToday, failedLoginsToday, passwordResetsThisWeek] =
      await Promise.all([
        this.prisma.auditLog.count({
          where: {
            tenantId,
            action: 'user.login',
            status: 'success',
            createdAt: { gte: todayStart },
          },
        }),
        this.prisma.auditLog.count({
          where: {
            tenantId,
            action: 'user.login_failed',
            createdAt: { gte: todayStart },
          },
        }),
        this.prisma.auditLog.count({
          where: {
            tenantId,
            action: 'user.password_reset_requested',
            createdAt: { gte: weekStart },
          },
        }),
      ]);

    // OAuth stats
    const [totalClients, tokensIssuedToday] = await Promise.all([
      this.prisma.oAuthClient.count({ where: { tenantId } }),
      this.prisma.auditLog.count({
        where: {
          tenantId,
          action: 'oauth.token_issued',
          createdAt: { gte: todayStart },
        },
      }),
    ]);

    return {
      users: {
        total: totalUsers,
        active: activeUsers,
        inactive: totalUsers - activeUsers,
        newThisWeek: newUsersThisWeek,
      },
      sessions: {
        activeSessions,
      },
      auth: {
        loginsToday,
        failedLoginsToday,
        passwordResetsThisWeek,
      },
      oauth: {
        totalClients,
        tokensIssuedToday,
      },
    };
  }

  /**
   * List users with pagination
   */
  async listUsers(
    tenantId: string,
    page = 1,
    limit = 20,
    search?: string,
    isActive?: boolean,
  ) {
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = { tenantId };
    if (typeof isActive === 'boolean') {
      where.isActive = isActive;
    }
    if (search) {
      where.OR = [
        { email: { contains: search, mode: 'insensitive' } },
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [users, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          isActive: true,
          emailVerified: true,
          lastLoginAt: true,
          createdAt: true,
          _count: {
            select: { sessions: true, userRoles: true },
          },
        },
      }),
      this.prisma.user.count({ where }),
    ]);

    return {
      data: users,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Get user details for admin
   */
  async getUserDetails(tenantId: string, userId: string) {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, tenantId },
      include: {
        userRoles: {
          include: {
            role: true,
          },
        },
        sessions: {
          where: {
            revokedAt: null,
            expiresAt: { gt: new Date() },
          },
          orderBy: { lastActiveAt: 'desc' },
          take: 10,
        },
        _count: {
          select: {
            authorizationCodes: true,
            oauthTokens: true,
          },
        },
      },
    });

    if (!user) {
      return null;
    }

    // Get recent activity
    const recentActivity = await this.prisma.auditLog.findMany({
      where: {
        tenantId,
        actorId: userId,
      },
      orderBy: { createdAt: 'desc' },
      take: 20,
    });

    return {
      ...user,
      recentActivity,
    };
  }

  /**
   * Deactivate user and revoke all sessions
   */
  async deactivateUser(tenantId: string, userId: string) {
    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: userId },
        data: { isActive: false },
      }),
      this.prisma.session.updateMany({
        where: { userId, tenantId, revokedAt: null },
        data: { revokedAt: new Date(), revokeReason: 'user_deactivated' },
      }),
    ]);
  }

  /**
   * Activate user
   */
  async activateUser(tenantId: string, userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { isActive: true },
    });
  }

  /**
   * Force logout user (revoke all sessions)
   */
  async forceLogout(tenantId: string, userId: string) {
    const result = await this.prisma.session.updateMany({
      where: { userId, tenantId, revokedAt: null },
      data: { revokedAt: new Date(), revokeReason: 'admin_action' },
    });

    return result.count;
  }

  /**
   * Get security overview - suspicious activity
   */
  async getSecurityOverview(tenantId: string) {
    const now = new Date();
    const todayStart = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate(),
    );
    // TODO: Add hourly granular suspicious activity detection

    // Recent failed logins
    const failedLogins = await this.prisma.auditLog.findMany({
      where: {
        tenantId,
        action: 'user.login_failed',
        createdAt: { gte: todayStart },
      },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });

    // Users with multiple failed attempts
    const failedLoginsByUser = failedLogins.reduce(
      (acc, log) => {
        const key = log.actorId || 'unknown';
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    );

    const suspiciousUsers = Object.entries(failedLoginsByUser)
      .filter(([_, count]) => count >= 3)
      .map(([userId, count]) => ({ userId, failedAttempts: count }));

    // Active sessions count
    const activeSessions = await this.prisma.session.findMany({
      where: {
        tenantId,
        revokedAt: null,
        expiresAt: { gt: now },
      },
      orderBy: { lastActiveAt: 'desc' },
      take: 100,
      include: {
        user: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
      },
    });

    return {
      failedLoginsToday: failedLogins.length,
      suspiciousUsers,
      activeSessions: activeSessions.length,
      recentSessions: activeSessions.slice(0, 20),
    };
  }

  /**
   * List active sessions across tenant
   */
  async listActiveSessions(tenantId: string, page = 1, limit = 50) {
    const skip = (page - 1) * limit;

    const [sessions, total] = await Promise.all([
      this.prisma.session.findMany({
        where: {
          tenantId,
          revokedAt: null,
          expiresAt: { gt: new Date() },
        },
        skip,
        take: limit,
        orderBy: { lastActiveAt: 'desc' },
        include: {
          user: {
            select: { id: true, email: true, firstName: true, lastName: true },
          },
        },
      }),
      this.prisma.session.count({
        where: {
          tenantId,
          revokedAt: null,
          expiresAt: { gt: new Date() },
        },
      }),
    ]);

    return {
      data: sessions,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Bulk revoke sessions
   */
  async bulkRevokeSessions(sessionIds: string[], reason = 'admin_action') {
    const result = await this.prisma.session.updateMany({
      where: { id: { in: sessionIds } },
      data: { revokedAt: new Date(), revokeReason: reason },
    });

    return result.count;
  }
}
