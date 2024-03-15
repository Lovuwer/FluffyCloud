import { SetMetadata } from '@nestjs/common';
import { AuditAction } from './audit-actions.js';

export const AUDIT_KEY = 'audit';

export interface AuditMetadata {
  action: AuditAction;
  resourceType: string;
}

/**
 * Audit decorator for automatic audit logging
 * Usage: @Audit(AuditAction.USER_CREATED, 'user')
 */
export const Audit = (action: AuditAction, resourceType: string) =>
  SetMetadata(AUDIT_KEY, { action, resourceType } as AuditMetadata);
