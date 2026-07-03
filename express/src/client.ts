/**
 * Repuwave Express Middleware — API Client.
 *
 * Calls GET /v1/verify/{uaid} with LRU caching.
 */

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
      minimumScore: config.minimumScore ?? 50,
      cacheTtlSeconds: config.cacheTtlSeconds ?? 300,
      uaidHeader: config.uaidHeader ?? "x-repuwave-uaid",
    };
  }

  /**
   * Verify an agent's reputation score.
   * Returns cached result if available, otherwise calls the Repuwave API.
   */
  async verify(uaid: string): Promise<VerificationResult> {
    // Check cache first
    const cached = this.cache.get(uaid);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.result;
    }

    // Call Repuwave API
    const url = `${this.config.apiUrl}/verify/${uaid}/`;
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "X-Service-API-Key": this.config.apiKey,
        "Content-Type": "application/json",
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
