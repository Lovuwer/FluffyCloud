import { Module } from '@nestjs/common';
import { RbacController } from './rbac.controller.js';
import { PermissionService } from './services/permission.service.js';
import { RoleService } from './services/role.service.js';

@Module({
  controllers: [RbacController],
  providers: [PermissionService, RoleService],
  exports: [PermissionService, RoleService],
})
export class RbacModule {}
