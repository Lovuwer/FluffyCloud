import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service.js';
import {
  CreateTaskDto,
  UpdateTaskDto,
  TaskStatusDto,
  TaskPriorityDto,
} from './dto/task.dto.js';
import { TaskStatus, TaskPriority } from '@prisma/client';

interface TaskFilters {
  status?: TaskStatusDto;
  priority?: TaskPriorityDto;
  assignedTo?: string;
  createdBy?: string;
}

/**
 * Task Service
 * Demo task management with tenant isolation
 */
@Injectable()
export class TaskService {
  constructor(private prisma: PrismaService) {}

  /**
   * Create a new task
   */
  async createTask(tenantId: string, createdBy: string, dto: CreateTaskDto) {
    const task = await this.prisma.task.create({
      data: {
        tenantId,
        createdBy,
        title: dto.title,
        description: dto.description,
        priority: (dto.priority as TaskPriority) || 'MEDIUM',
        assignedTo: dto.assignedTo,
        dueDate: dto.dueDate ? new Date(dto.dueDate) : null,
      },
      include: {
        assignee: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
        creator: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
      },
    });

    return task;
  }

  /**
   * Get task by ID
   */
  async getTask(tenantId: string, taskId: string) {
    const task = await this.prisma.task.findFirst({
      where: { id: taskId, tenantId },
      include: {
        assignee: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
        creator: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
      },
    });

    if (!task) {
      throw new NotFoundException('Task not found');
    }

    return task;
  }

  /**
   * List tasks with filtering
   */
  async listTasks(tenantId: string, filters: TaskFilters = {}) {
    const where: Record<string, unknown> = { tenantId };

    if (filters.status) {
      where.status = filters.status as TaskStatus;
    }
    if (filters.priority) {
      where.priority = filters.priority as TaskPriority;
    }
    if (filters.assignedTo) {
      where.assignedTo = filters.assignedTo;
    }
    if (filters.createdBy) {
      where.createdBy = filters.createdBy;
    }

    const tasks = await this.prisma.task.findMany({
      where,
      orderBy: [{ priority: 'desc' }, { createdAt: 'desc' }],
      include: {
        assignee: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
        creator: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
      },
    });

    return tasks;
  }

  /**
   * Update task
   */
  async updateTask(
    tenantId: string,
    taskId: string,
    userId: string,
    dto: UpdateTaskDto,
    hasFullAccess: boolean,
  ) {
    const task = await this.getTask(tenantId, taskId);

    // Check ownership if user only has 'own' permission
    if (
      !hasFullAccess &&
      task.createdBy !== userId &&
      task.assignedTo !== userId
    ) {
      throw new ForbiddenException('You can only update your own tasks');
    }

    const updated = await this.prisma.task.update({
      where: { id: taskId },
      data: {
        title: dto.title,
        description: dto.description,
        status: dto.status as TaskStatus,
        priority: dto.priority as TaskPriority,
        dueDate: dto.dueDate ? new Date(dto.dueDate) : undefined,
      },
      include: {
        assignee: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
        creator: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
      },
    });

    return updated;
  }

  /**
   * Assign task to user
   */
  async assignTask(tenantId: string, taskId: string, userId: string) {
    // Verify task exists in tenant
    await this.getTask(tenantId, taskId);

    // Verify user exists in tenant
    const user = await this.prisma.user.findFirst({
      where: { id: userId, tenantId },
    });

    if (!user) {
      throw new NotFoundException('User not found in tenant');
    }

    const updated = await this.prisma.task.update({
      where: { id: taskId },
      data: { assignedTo: userId },
      include: {
        assignee: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
        creator: {
          select: { id: true, email: true, firstName: true, lastName: true },
        },
      },
    });

    return updated;
  }

  /**
   * Delete task (soft delete by setting status)
   */
  async deleteTask(tenantId: string, taskId: string) {
    await this.getTask(tenantId, taskId);

    await this.prisma.task.delete({
      where: { id: taskId },
    });
  }
}
