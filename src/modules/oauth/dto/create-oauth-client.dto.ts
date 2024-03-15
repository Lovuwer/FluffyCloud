import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsArray,
  IsBoolean,
  IsUrl,
  ArrayMinSize,
} from 'class-validator';

export class CreateOAuthClientDto {
  @IsString()
  @IsNotEmpty()
  name!: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsOptional()
  tenantId?: string; // null = platform-level client

  @IsArray()
  @ArrayMinSize(1)
  @IsUrl({}, { each: true })
  redirectUris!: string[];

  @IsArray()
  @IsString({ each: true })
  allowedGrantTypes!: string[]; // authorization_code, refresh_token, client_credentials

  @IsArray()
  @IsString({ each: true })
  allowedScopes!: string[];

  @IsBoolean()
  @IsOptional()
  isConfidential?: boolean;
}
