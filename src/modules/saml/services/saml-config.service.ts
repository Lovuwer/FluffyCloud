import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * SAML Configuration Service
 * Generates SP metadata and manages SP configuration
 */
@Injectable()
export class SamlConfigService {
  private domain: string;

  constructor(private configService: ConfigService) {
    this.domain = this.configService.get<string>(
      'APP_DOMAIN',
      'http://localhost:3000',
    );
  }

  /**
   * Get SP Entity ID for a tenant
   */
  getEntityId(tenantSlug: string): string {
    return `${this.domain}/saml/metadata/${tenantSlug}`;
  }

  /**
   * Get Assertion Consumer Service URL for a tenant
   */
  getAcsUrl(tenantSlug: string): string {
    return `${this.domain}/saml/acs/${tenantSlug}`;
  }

  /**
   * Get Single Logout URL for a tenant
   */
  getSloUrl(tenantSlug: string): string {
    return `${this.domain}/saml/slo/${tenantSlug}`;
  }

  /**
   * Generate SP Metadata XML for a tenant
   */
  generateMetadataXml(tenantSlug: string): string {
    const entityId = this.getEntityId(tenantSlug);
    const acsUrl = this.getAcsUrl(tenantSlug);
    const sloUrl = this.getSloUrl(tenantSlug);

    // TODO: Add SP certificate for signed requests
    return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="${this.escapeXml(entityId)}">
  <md:SPSSODescriptor AuthnRequestsSigned="false"
                      WantAssertionsSigned="true"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                  Location="${this.escapeXml(acsUrl)}"
                                  index="0"
                                  isDefault="true"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="${this.escapeXml(sloUrl)}"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;
  }

  private escapeXml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }
}
