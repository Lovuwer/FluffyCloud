import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsUUID,
  IsDateString,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum TaskStatusDto {
  TODO = 'TODO',
  IN_PROGRESS = 'IN_PROGRESS',
  DONE = 'DONE',
}

export enum TaskPriorityDto {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
}

export class CreateTaskDto {
  @ApiProperty({
    description: 'Task title',
    example: 'Complete project documentation',
  })
  @IsString()
  @IsNotEmpty()
  title!: string;

  @ApiPropertyOptional({ description: 'Task description' })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiPropertyOptional({
    enum: TaskPriorityDto,
    default: TaskPriorityDto.MEDIUM,
  })
  @IsEnum(TaskPriorityDto)
  @IsOptional()
  priority?: TaskPriorityDto;

  @ApiPropertyOptional({ description: 'User ID to assign task to' })
  @IsUUID()
  @IsOptional()
  assignedTo?: string;

  @ApiPropertyOptional({ description: 'Due date' })
  @IsDateString()
  @IsOptional()
  dueDate?: string;
}

export class UpdateTaskDto {
  @ApiPropertyOptional({ description: 'Task title' })
  @IsString()
  @IsOptional()
  title?: string;

  @ApiPropertyOptional({ description: 'Task description' })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiPropertyOptional({ enum: TaskStatusDto })
  @IsEnum(TaskStatusDto)
  @IsOptional()
  status?: TaskStatusDto;

  @ApiPropertyOptional({ enum: TaskPriorityDto })
  @IsEnum(TaskPriorityDto)
  @IsOptional()
  priority?: TaskPriorityDto;

  @ApiPropertyOptional({ description: 'Due date' })
  @IsDateString()
  @IsOptional()
  dueDate?: string;
}

export class AssignTaskDto {
  @ApiProperty({ description: 'User ID to assign task to' })
  @IsUUID()
  userId!: string;
}
