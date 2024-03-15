import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service.js';
import { PasswordService } from './services/password.service.js';
import { TokenService } from './services/token.service.js';
import { RegisterDto } from './dto/register.dto.js';

// TODO: Add more granular error codes for different failure scenarios

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private passwordService: PasswordService,
    private tokenService: TokenService,
  ) {}

  async register(dto: RegisterDto) {
    // Get tenant - use 'system' as default if not specified
    const tenantSlug = dto.tenantSlug || 'system';
    const tenant = await this.prisma.tenant.findUnique({
      where: { slug: tenantSlug },
    });

    if (!tenant) {
      throw new NotFoundException(`Tenant '${tenantSlug}' not found`);
    }

    // Check if email already exists for this tenant
    const existingUser = await this.prisma.user.findUnique({
      where: {
        tenantId_email: {
          tenantId: tenant.id,
          email: dto.email,
        },
      },
    });

    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    // Hash password
    const passwordHash = await this.passwordService.hashPassword(dto.password);

    // Get the default "user" role for this tenant
    const userRole = await this.prisma.role.findFirst({
      where: {
        tenantId: tenant.id,
        name: 'user',
      },
    });

    // Create user with transaction to ensure atomicity
    const user = await this.prisma.$transaction(async (tx) => {
      const newUser = await tx.user.create({
        data: {
          tenantId: tenant.id,
          email: dto.email,
          passwordHash,
          firstName: dto.firstName,
          lastName: dto.lastName,
          emailVerified: false,
          isActive: true,
        },
      });

      // Assign default role if it exists
      if (userRole) {
        await tx.userRole.create({
          data: {
            userId: newUser.id,
            roleId: userRole.id,
            tenantId: tenant.id,
          },
        });
      }

      return newUser;
    });

    // Return user data without password hash
    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      tenantId: user.tenantId,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
      createdAt: user.createdAt,
    };
  }

  async validateUser(email: string, password: string, tenantSlug?: string) {
    // Get tenant
    const slug = tenantSlug || 'system';
    const tenant = await this.prisma.tenant.findUnique({
      where: { slug },
    });

    if (!tenant) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Find user
    const user = await this.prisma.user.findUnique({
      where: {
        tenantId_email: {
          tenantId: tenant.id,
          email,
        },
      },
    });

    if (!user || !user.passwordHash) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is disabled');
    }

    // Verify password
    const isPasswordValid = await this.passwordService.verifyPassword(
      password,
      user.passwordHash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Update last login
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    return user;
  }

  async login(email: string, password: string, tenantSlug?: string) {
    const user = await this.validateUser(email, password, tenantSlug);

    // Get user's roles and permissions
    const userRoles = await this.prisma.userRole.findMany({
      where: { userId: user.id },
      include: {
        role: {
          include: {
            rolePermissions: {
              include: {
                permission: true,
              },
            },
          },
        },
      },
    });

    const roles = userRoles.map((ur) => ur.role.name);
    const permissions = [
      ...new Set(
        userRoles.flatMap((ur) =>
          ur.role.rolePermissions.map((rp) => rp.permission.name),
        ),
      ),
    ];

    // Generate tokens
    const accessToken = this.tokenService.generateAccessToken(
      { id: user.id, email: user.email },
      user.tenantId,
      roles,
      permissions,
    );

    const refreshToken = await this.tokenService.generateRefreshToken(
      user.id,
      user.tenantId,
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: this.tokenService.getAccessTokenExpirySeconds(),
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        roles,
      },
    };
  }

  async refreshTokens(refreshToken: string) {
    const payload = await this.tokenService.verifyRefreshToken(refreshToken);

    // Get user
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user || !user.isActive) {
      throw new UnauthorizedException('User not found or inactive');
    }

    // Get roles and permissions
    const userRoles = await this.prisma.userRole.findMany({
      where: { userId: user.id },
      include: {
        role: {
          include: {
            rolePermissions: {
              include: {
                permission: true,
              },
            },
          },
        },
      },
    });

    const roles = userRoles.map((ur) => ur.role.name);
    const permissions = [
      ...new Set(
        userRoles.flatMap((ur) =>
          ur.role.rolePermissions.map((rp) => rp.permission.name),
        ),
      ),
    ];

    // Revoke old refresh token
    await this.tokenService.revokeRefreshToken(payload.jti);

    // Generate new tokens
    const accessToken = this.tokenService.generateAccessToken(
      { id: user.id, email: user.email },
      user.tenantId,
      roles,
      permissions,
    );

    const newRefreshToken = await this.tokenService.generateRefreshToken(
      user.id,
      user.tenantId,
    );

    return {
      accessToken,
      refreshToken: newRefreshToken,
      expiresIn: this.tokenService.getAccessTokenExpirySeconds(),
    };
  }

  async logout(refreshToken: string) {
    try {
      const payload = await this.tokenService.verifyRefreshToken(refreshToken);
      await this.tokenService.revokeRefreshToken(payload.jti);
    } catch {
      // Token might already be invalid/expired, that's fine
    }
  }
}
