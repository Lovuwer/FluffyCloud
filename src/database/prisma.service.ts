import {
  Injectable,
  OnModuleInit,
  OnModuleDestroy,
  Logger,
} from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

// TODO: Consider implementing row-level security (RLS) in PostgreSQL as an additional
// layer of tenant isolation protection. RLS policies can enforce tenant_id filtering
// at the database level, providing defense-in-depth even if application logic is bypassed.
// Reference: https://www.prisma.io/docs/guides/database/multi-tenancy

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(PrismaService.name);

  async onModuleInit() {
    await this.$connect();
    this.logger.log('Database connected');
  }

  async onModuleDestroy() {
    await this.$disconnect();
    this.logger.log('Database disconnected');
  }
}
