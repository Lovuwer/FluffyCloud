import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';

/**
 * Require specific roles to access a route
 * Use @Roles('admin', 'manager') decorator on controller or method
 */
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
