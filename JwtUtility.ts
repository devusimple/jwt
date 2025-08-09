import * as crypto from 'crypto';

interface JwtHeader {
  alg: string;
  typ: string;
}

interface JwtPayload {
  [key: string]: any;
  exp?: number;
  nbf?: number;
  iat?: number;
  iss?: string;
  sub?: string;
  aud?: string | string[];
}

class JwtUtility {
  private static readonly ALGORITHMS: { [key: string]: string } = {
    HS256: 'sha256',
    HS384: 'sha384',
    HS512: 'sha512'
  };

  private static readonly ENCODING = 'base64url';
  private static readonly UTF8 = 'utf8';

  /**
   * Generates a JWT token
   * @param payload - The payload data
   * @param secret - The secret key for signing
   * @param options - Configuration options
   * @returns Signed JWT token
   */
  static generate(
    payload: JwtPayload,
    secret: string,
    options: {
      algorithm?: 'HS256' | 'HS384' | 'HS512';
      expiresIn?: string | number;
      notBefore?: string | number;
      issuer?: string;
      subject?: string;
      audience?: string | string[];
    } = {}
  ): string {
    const algorithm = options.algorithm || 'HS256';
    const alg = this.ALGORITHMS[algorithm];
    if (!alg) throw new Error(`Unsupported algorithm: ${algorithm}`);

    // Process payload
    const now = Math.floor(Date.now() / 1000);
    const processedPayload: JwtPayload = { ...payload };

    // Handle expiration
    if (options.expiresIn !== undefined) {
      const exp = this.parseTimeOption(options.expiresIn);
      processedPayload.exp = now + exp;
    }

    // Handle not before
    if (options.notBefore !== undefined) {
      const nbf = this.parseTimeOption(options.notBefore);
      processedPayload.nbf = now + nbf;
    }

    // Add standard claims
    if (!processedPayload.iat) processedPayload.iat = now;
    if (options.issuer) processedPayload.iss = options.issuer;
    if (options.subject) processedPayload.sub = options.subject;
    if (options.audience) processedPayload.aud = options.audience;

    // Create header
    const header: JwtHeader = { alg: algorithm, typ: 'JWT' };

    // Encode parts
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(processedPayload));

    // Create signature
    const signature = this.createSignature(`${encodedHeader}.${encodedPayload}`, secret, alg);

    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  /**
   * Verifies a JWT token
   * @param token - The JWT token to verify
   * @param secret - The secret key for verification
   * @returns True if valid, false otherwise
   */
  static verify(token: string, secret: string): boolean {
    try {
      this.decode(token, secret);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Decodes and validates a JWT token
   * @param token - The JWT token to decode
   * @param secret - The secret key for verification
   * @returns Decoded payload
   */
  static decode(token: string, secret: string): JwtPayload {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token format');

    const [encodedHeader, encodedPayload, signature] = parts;

    // Decode header and payload
    const header: JwtHeader = JSON.parse(this.base64UrlDecode(encodedHeader));
    const payload: JwtPayload = JSON.parse(this.base64UrlDecode(encodedPayload));

    // Validate algorithm
    const alg = this.ALGORITHMS[header.alg];
    if (!alg) throw new Error(`Unsupported algorithm: ${header.alg}`);

    // Verify signature
    const expectedSignature = this.createSignature(`${encodedHeader}.${encodedPayload}`, secret, alg);
    if (signature !== expectedSignature) throw new Error('Invalid signature');

    // Validate claims
    const now = Math.floor(Date.now() / 1000);
    
    if (payload.exp !== undefined && payload.exp < now) {
      throw new Error('Token expired');
    }
    
    if (payload.nbf !== undefined && payload.nbf > now) {
      throw new Error('Token not yet valid');
    }

    return payload;
  }

  /**
   * Gets the payload without verification
   * @param token - The JWT token
   * @returns Decoded payload
   */
  static getPayload(token: string): JwtPayload {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token format');
    
    return JSON.parse(this.base64UrlDecode(parts[1]));
  }

  /**
   * Gets the header without verification
   * @param token - The JWT token
   * @returns Decoded header
   */
  static getHeader(token: string): JwtHeader {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token format');
    
    return JSON.parse(this.base64UrlDecode(parts[0]));
  }

  /**
   * Checks if token is expired
   * @param token - The JWT token
   * @returns True if expired, false otherwise
   */
  static isExpired(token: string): boolean {
    try {
      const payload = this.getPayload(token);
      if (payload.exp === undefined) return false;
      
      return payload.exp < Math.floor(Date.now() / 1000);
    } catch {
      return true;
    }
  }

  /**
   * Refreshes a token with new expiration
   * @param token - The JWT token to refresh
   * @param secret - The secret key
   * @param expiresIn - New expiration time
   * @returns New JWT token
   */
  static refreshToken(
    token: string,
    secret: string,
    expiresIn: string | number
  ): string {
    const payload = this.getPayload(token);
    delete payload.exp;
    delete payload.iat;
    delete payload.nbf;

    return this.generate(payload, secret, { expiresIn });
  }

  // Private helper methods
  private static createSignature(input: string, secret: string, algorithm: string): string {
    return crypto
      .createHmac(algorithm, secret)
      .update(input)
      .digest(this.ENCODING);
  }

  private static base64UrlEncode(str: string): string {
    return Buffer.from(str, this.UTF8).toString(this.ENCODING);
  }

  private static base64UrlDecode(str: string): string {
    return Buffer.from(str, this.ENCODING).toString(this.UTF8);
  }

  private static parseTimeOption(time: string | number): number {
    if (typeof time === 'number') return time;
    
    const match = time.match(/^(\d+)([smhd])$/);
    if (!match) throw new Error('Invalid time format');
    
    const value = parseInt(match[1], 10);
    const unit = match[2];
    
    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 3600;
      case 'd': return value * 86400;
      default: throw new Error('Invalid time unit');
    }
  }
}

export default JwtUtility;
export { JwtPayload, JwtHeader };
