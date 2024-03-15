import {
  IsString,
  IsOptional,
  IsArray,
  IsBoolean,
  IsUrl,
} from 'class-validator';

export class UpdateOAuthClientDto {
  @IsString()
  @IsOptional()
  name?: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsArray()
  @IsUrl({}, { each: true })
  @IsOptional()
  redirectUris?: string[];

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  allowedGrantTypes?: string[];

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  allowedScopes?: string[];

  @IsBoolean()
  @IsOptional()
  isConfidential?: boolean;

  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}
