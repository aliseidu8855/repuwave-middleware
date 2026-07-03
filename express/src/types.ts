/**
 * Repuwave Express Middleware — Types.
 */

export interface RepuwaveConfig {
  /** Repuwave API base URL (e.g., "https://api.repuwave.io/v1") */
  apiUrl: string;
  /** Service API key for authenticating with Repuwave */
  apiKey: string;
  /** Minimum score required to allow the request (default: 50) */
  minimumScore?: number;
  /** Cache TTL in seconds (default: 300) */
  cacheTtlSeconds?: number;
  /** Custom header to extract UAID from (default: "x-repuwave-uaid") */
  uaidHeader?: string;
  /** How to handle unsigned/failed requests: 'enforce' (block) or 'audit' (pass-through) */
  enforceMode?: 'enforce' | 'audit';
  /** URL to redirect blocked developers to (default: "https://repuwave.fasolink.app") */
  signupUrl?: string;
}

export interface VerificationResult {
  verified: boolean;
  score: number;
  status: string;
  uaid: string;
  public_key?: string;
}

export interface RepuwaveRequest {
  repuwave?: VerificationResult;
}
