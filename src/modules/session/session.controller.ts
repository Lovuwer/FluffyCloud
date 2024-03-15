import {
  Controller,
  Get,
  Delete,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
  Req,
} from '@nestjs/common';
import type { Request } from 'express';
import { SessionService, SessionData } from './session.service.js';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard.js';
import { CurrentUser } from '../../common/decorators/current-user.decorator.js';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
} from '@nestjs/swagger';

interface RequestUser {
  userId: string;
  tenantId: string;
  roles: string[];
}

/**
 * Session Controller
 * Manages user sessions
 */
@Controller('sessions')
@UseGuards(JwtAuthGuard)
@ApiTags('Sessions')
@ApiBearerAuth()
export class SessionController {
  constructor(private sessionService: SessionService) {}

  @Get()
  @ApiOperation({ summary: 'List my active sessions' })
  @ApiResponse({ status: 200, description: 'Returns list of active sessions' })
  async listSessions(@CurrentUser() user: RequestUser): Promise<SessionData[]> {
    return this.sessionService.getActiveSessions(user.userId);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Revoke a specific session' })
  @ApiResponse({ status: 204, description: 'Session revoked' })
  @HttpCode(HttpStatus.NO_CONTENT)
  async revokeSession(
    @Param('id') id: string,
    @CurrentUser() user: RequestUser,
  ) {
    // Verify the session belongs to the user
    const sessions = await this.sessionService.getActiveSessions(user.userId);
    const session = sessions.find((s) => s.id === id);
    if (session) {
      await this.sessionService.revokeSession(id, 'user_logout');
    }
  }

  @Delete()
  @ApiOperation({
    summary: 'Revoke all sessions except current (logout everywhere)',
  })
  @ApiResponse({
    status: 200,
    description: 'Returns count of revoked sessions',
  })
  async revokeAllSessions(
    @CurrentUser() user: RequestUser,
    @Req() req: Request,
  ) {
    // Get current session ID from request if available
    const currentSessionId = (req as unknown as { sessionId?: string })
      .sessionId;

    const count = await this.sessionService.revokeAllUserSessions(
      user.userId,
      currentSessionId,
      'logout_everywhere',
    );

    return { revokedCount: count };
  }
}
