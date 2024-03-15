import { Injectable } from '@nestjs/common';
import bcrypt from 'bcrypt';

/**
 * Password Service
 *
 * Uses bcrypt for password hashing with a cost factor of 12.
 * Why 12? It provides a good balance between security and performance:
 * - Each increment doubles the computation time
 * - 12 rounds takes ~250ms on modern hardware
 * - This is slow enough to deter brute force attacks but fast enough for good UX
 *
 * TODO: Make cost factor configurable via env var (BCRYPT_COST_FACTOR)
 */
@Injectable()
export class PasswordService {
  // Cost factor of 12 provides ~250ms hash time, good security/performance balance
  private readonly COST_FACTOR = 12;

  async hashPassword(plainPassword: string): Promise<string> {
    return bcrypt.hash(plainPassword, this.COST_FACTOR);
  }

  async verifyPassword(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(plainPassword, hashedPassword);
  }

  /**
   * Validates password strength against our requirements
   * TODO: Make these rules configurable via env vars
   */
  validatePasswordStrength(password: string): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}
