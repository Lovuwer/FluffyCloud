import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { TaskService } from './task.service.js';
import {
  CreateTaskDto,
  UpdateTaskDto,
  AssignTaskDto,
  TaskStatusDto,
  TaskPriorityDto,
} from './dto/task.dto.js';
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
  permissions: string[];
}

/**
 * Task Controller
 * Demo task management API showcasing IAM features
 */
@Controller('demo/tasks')
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiTags('Demo - Tasks')
@ApiBearerAuth()
export class TaskController {
  constructor(private taskService: TaskService) {}

  @Get()
  @Permissions('tasks:list')
  @ApiOperation({ summary: 'List tasks in tenant' })
  @ApiQuery({ name: 'status', required: false, enum: TaskStatusDto })
  @ApiQuery({ name: 'priority', required: false, enum: TaskPriorityDto })
  @ApiQuery({ name: 'assignedTo', required: false, type: String })
  @ApiResponse({ status: 200, description: 'Returns list of tasks' })
  async listTasks(
    @CurrentUser() user: RequestUser,
    @Query('status') status?: TaskStatusDto,
    @Query('priority') priority?: TaskPriorityDto,
    @Query('assignedTo') assignedTo?: string,
  ) {
    return this.taskService.listTasks(user.tenantId, {
      status,
      priority,
      assignedTo,
    });
  }

  @Get(':id')
  @Permissions('tasks:read')
  @ApiOperation({ summary: 'Get task by ID' })
  @ApiResponse({ status: 200, description: 'Returns task details' })
  @ApiResponse({ status: 404, description: 'Task not found' })
  async getTask(@CurrentUser() user: RequestUser, @Param('id') id: string) {
    return this.taskService.getTask(user.tenantId, id);
  }

  @Post()
  @Permissions('tasks:create')
  @ApiOperation({ summary: 'Create a new task' })
  @ApiResponse({ status: 201, description: 'Task created' })
  @HttpCode(HttpStatus.CREATED)
  async createTask(
    @CurrentUser() user: RequestUser,
    @Body() dto: CreateTaskDto,
  ) {
    return this.taskService.createTask(user.tenantId, user.userId, dto);
  }

  @Patch(':id')
  @Permissions('tasks:update', 'tasks:update:own')
  @ApiOperation({ summary: 'Update task' })
  @ApiResponse({ status: 200, description: 'Task updated' })
  @ApiResponse({
    status: 403,
    description: 'Not authorized to update this task',
  })
  async updateTask(
    @CurrentUser() user: RequestUser,
    @Param('id') id: string,
    @Body() dto: UpdateTaskDto,
  ) {
    // Check if user has full update permission or only own
    const hasFullAccess = user.permissions.includes('tasks:update');
    return this.taskService.updateTask(
      user.tenantId,
      id,
      user.userId,
      dto,
      hasFullAccess,
    );
  }

  @Patch(':id/assign')
  @Permissions('tasks:assign')
  @ApiOperation({ summary: 'Assign task to user' })
  @ApiResponse({ status: 200, description: 'Task assigned' })
  async assignTask(
    @CurrentUser() user: RequestUser,
    @Param('id') id: string,
    @Body() dto: AssignTaskDto,
  ) {
    return this.taskService.assignTask(user.tenantId, id, dto.userId);
  }

  @Delete(':id')
  @Permissions('tasks:delete')
  @ApiOperation({ summary: 'Delete task' })
  @ApiResponse({ status: 204, description: 'Task deleted' })
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteTask(@CurrentUser() user: RequestUser, @Param('id') id: string) {
    await this.taskService.deleteTask(user.tenantId, id);
  }
}
