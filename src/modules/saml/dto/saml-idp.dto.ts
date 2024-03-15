import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsBoolean,
  IsUrl,
  IsObject,
} from 'class-validator';

export class CreateSamlIdpDto {
  @IsString()
  @IsNotEmpty()
  name!: string;

  @IsString()
  @IsNotEmpty()
  entityId!: string;

  @IsUrl()
  @IsNotEmpty()
  ssoUrl!: string;

  @IsUrl()
  @IsOptional()
  sloUrl?: string;

  @IsString()
  @IsNotEmpty()
  certificate!: string;

  @IsString()
  @IsOptional()
  nameIdFormat?: string;

  @IsObject()
  @IsOptional()
  attributeMapping?: Record<string, string>;
}

export class UpdateSamlIdpDto {
  @IsString()
  @IsOptional()
  name?: string;

  @IsString()
  @IsOptional()
  entityId?: string;

  @IsUrl()
  @IsOptional()
  ssoUrl?: string;

  @IsUrl()
  @IsOptional()
  sloUrl?: string;

  @IsString()
  @IsOptional()
  certificate?: string;

  @IsString()
  @IsOptional()
  nameIdFormat?: string;

  @IsObject()
  @IsOptional()
  attributeMapping?: Record<string, string>;

  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}
