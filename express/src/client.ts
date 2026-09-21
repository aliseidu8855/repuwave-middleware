/**
 * Repuwave Express Middleware — API Client.
 *
 * Calls GET /v1/verify/{uaid} with LRU caching.
 */

import { REPUWAVE_DEFAULTS } from "./types";
import type { RepuwaveConfig, VerificationResult } from "./types";

interface CacheEntry {
  result: VerificationResult;
  expiresAt: number;
}

export class RepuwaveApiClient {
  private config: Required<RepuwaveConfig>;
  private cache: Map<string, CacheEntry> = new Map();

  constructor(config: RepuwaveConfig) {
    this.config = {
      apiUrl: config.apiUrl,
      apiKey: config.apiKey,
      minimumScore: config.minimumScore ?? REPUWAVE_DEFAULTS.minimumScore,
      cacheTtlSeconds: config.cacheTtlSeconds ?? REPUWAVE_DEFAULTS.cacheTtlSeconds,
      uaidHeader: config.uaidHeader ?? REPUWAVE_DEFAULTS.uaidHeader,
      enforceMode: config.enforceMode ?? REPUWAVE_DEFAULTS.enforceMode,
      signupUrl: config.signupUrl ?? REPUWAVE_DEFAULTS.signupUrl,
      failureMode: config.failureMode ?? REPUWAVE_DEFAULTS.failureMode,
    };
  }

  /**
   * Verify an agent's reputation score.
   * Returns cached result if available, otherwise calls the Repuwave API.
   */
  /**
   * @param proof - The agent's own signature headers, forwarded to the server.
   *   GET /v1/verify/ checks the signature and refuses without it: a UAID alone
   *   proves nothing, because UAIDs are public in the key directory.
   */
  async verify(
    uaid: string,
    proof?: { signature?: string; timestamp?: string; bodyHash?: string },
  ): Promise<VerificationResult> {
    // The cache is only consultable by a caller that presented a signature.
    //
    // It is keyed on the UAID alone and was checked before the API call, so
    // once any legitimate signed request for a UAID had been cached, a second
    // caller could present that UAID with NO signature, hit the cache, never
    // reach the server, and be admitted. The server-side signature requirement
    // was defeated for the whole TTL -- 300 seconds by default.
    //
    // A signed caller is still safe to serve from cache because middleware.ts
    // verifies the signature locally against the cached public_key on every
    // request, hit or miss.
    if (proof?.signature && proof?.timestamp) {
      const cached = this.cache.get(uaid);
      if (cached && cached.expiresAt > Date.now()) {
        return cached.result;
      }
    }

    // Call Repuwave API
    const url = `${this.config.apiUrl}/verify/${uaid}/`;
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "X-Service-API-Key": this.config.apiKey,
        "Content-Type": "application/json",
        ...(proof?.signature ? { "X-Repuwave-Signature": proof.signature } : {}),
        ...(proof?.timestamp ? { "X-Repuwave-Timestamp": proof.timestamp } : {}),
        ...(proof?.bodyHash ? { "X-Repuwave-Body-Hash": proof.bodyHash } : {}),
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        return { verified: false, score: 0, status: "UNKNOWN", uaid };
      }
      throw new Error(
        `Repuwave API error: ${response.status} ${response.statusText}`
      );
    }

    const result: VerificationResult = await response.json();

    // Cache the result
    this.cache.set(uaid, {
      result,
      expiresAt: Date.now() + this.config.cacheTtlSeconds * 1000,
    });

    // Evict old entries (simple LRU: cap at 1000)
    if (this.cache.size > 1000) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) this.cache.delete(firstKey);
    }

    return result;
  }

  /** Clear the verification cache. */
  clearCache(): void {
    this.cache.clear();
  }

  get minimumScore(): number {
    return this.config.minimumScore;
  }

  get uaidHeader(): string {
    return this.config.uaidHeader;
  }
}
