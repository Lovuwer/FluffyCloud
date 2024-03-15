import { IsString, IsOptional, IsBoolean, IsObject } from 'class-validator';

export class UpdateTenantDto {
  @IsString()
  @IsOptional()
  name?: string;

  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}

export interface TenantSettings {
  allowSelfRegistration: boolean;
  requireEmailVerification: boolean;
  passwordPolicy: {
    minLength: number;
    requireUppercase: boolean;
    requireNumber: boolean;
    requireSpecial: boolean;
  };
  sessionTimeout: number; // minutes
  mfaRequired: boolean;
  allowedDomains: string[]; // email domains allowed to register
  brandingConfig?: {
    logoUrl?: string;
    primaryColor?: string;
    companyName?: string;
  };
}

export class UpdateTenantSettingsDto {
  @IsBoolean()
  @IsOptional()
  allowSelfRegistration?: boolean;

  @IsBoolean()
  @IsOptional()
  requireEmailVerification?: boolean;

  @IsObject()
  @IsOptional()
  passwordPolicy?: {
    minLength?: number;
    requireUppercase?: boolean;
    requireNumber?: boolean;
    requireSpecial?: boolean;
  };

  @IsOptional()
  sessionTimeout?: number;

  @IsBoolean()
  @IsOptional()
  mfaRequired?: boolean;

  @IsOptional()
  allowedDomains?: string[];

  @IsObject()
  @IsOptional()
  brandingConfig?: {
    logoUrl?: string;
    primaryColor?: string;
    companyName?: string;
  };
}
