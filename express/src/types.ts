/**
 * Repuwave Express Middleware — Types.
 */

export interface RepuwaveConfig {
  /** Repuwave API base URL (e.g., "https://repuwave.fasolink.app/v1") */
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

/**
 * The defaults, in one place.
 *
 * `client.ts` and `middleware.ts` each applied their own, which is how
 * client.ts came to omit `enforceMode` and `signupUrl` entirely once they were
 * added to RepuwaveConfig -- the package stopped typechecking and nothing
 * reported it, because this repository had no CI.
 *
 * `enforceMode` defaults to 'enforce' deliberately. A middleware whose default
 * is to let unverified traffic through is a middleware that does nothing until
 * someone reads the documentation.
 */
export const REPUWAVE_DEFAULTS = {
  minimumScore: 50,
  cacheTtlSeconds: 300,
  uaidHeader: "x-repuwave-uaid",
  enforceMode: "enforce",
  signupUrl: "https://repuwave.fasolink.app",
} as const;
