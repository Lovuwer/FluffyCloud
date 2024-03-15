import { Injectable } from '@nestjs/common';
import { AsyncLocalStorage } from 'async_hooks';

interface TenantContext {
  tenantId: string;
  tenantSlug?: string;
}

/**
 * Tenant Context Service
 * Uses AsyncLocalStorage to maintain tenant context across async operations
 */
@Injectable()
export class TenantContextService {
  private storage = new AsyncLocalStorage<TenantContext>();

  /**
   * Set the current tenant context
   */
  setTenant(tenantId: string, tenantSlug?: string): void {
    const store = this.storage.getStore();
    if (store) {
      store.tenantId = tenantId;
      store.tenantSlug = tenantSlug;
    }
  }

  /**
   * Get the current tenant ID
   */
  getTenantId(): string | undefined {
    return this.storage.getStore()?.tenantId;
  }

  /**
   * Get the current tenant slug
   */
  getTenantSlug(): string | undefined {
    return this.storage.getStore()?.tenantSlug;
  }

  /**
   * Get the full tenant context
   */
  getContext(): TenantContext | undefined {
    return this.storage.getStore();
  }

  /**
   * Run a function within a tenant context
   */
  run<T>(context: TenantContext, fn: () => T): T {
    return this.storage.run(context, fn);
  }

  /**
   * Run an async function within a tenant context
   */
  async runAsync<T>(context: TenantContext, fn: () => Promise<T>): Promise<T> {
    return this.storage.run(context, fn);
  }
}
