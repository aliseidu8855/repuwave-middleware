/**
 * Repuwave Express Middleware — Reputation Guard.
 *
 * Factory function that creates an Express middleware to gate
 * incoming requests based on agent reputation scores.
 *
 * Usage:
 *   import { repuwaveGuard } from "@repuwave/express-middleware";
 *
 *   app.use(repuwaveGuard({
 *     apiUrl: "https://api.repuwave.io/v1",
 *     apiKey: process.env.REPUWAVE_API_KEY!,
 *     minimumScore: 60,
 *   }));
 */

import type { Request, Response, NextFunction } from "express";
import { RepuwaveApiClient } from "./client";
import type { RepuwaveConfig, RepuwaveRequest, VerificationResult } from "./types";

/**
 * Create a Repuwave reputation guard middleware.
 *
 * Flow:
 *   1. Extract X-Repuwave-UAID from request headers
 *   2. Check LRU cache for recent verification
 *   3. If cache miss: call Repuwave API GET /v1/verify/{uaid}
 *   4. If score >= minimumScore → next()
 *   5. If score < threshold → 403
 *   6. Attach req.repuwave = {uaid, score, verified} for downstream use
 */
export function repuwaveGuard(config: RepuwaveConfig) {
  const client = new RepuwaveApiClient(config);

  return async (
    req: Request & RepuwaveRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const uaid = req.headers[client.uaidHeader] as string | undefined;
    const enforceMode = config.enforceMode || 'enforce';
    const signupUrl = config.signupUrl || 'https://repuwave.fasolink.app';
    const minScore = config.minimumScore || 50;

    const viralResponse = {
      error: "Untrusted Agent",
      message: `This endpoint requires a Repuwave Trust Score of ${minScore}+. Get verified at ${signupUrl}`
    };

    if (!uaid) {
      if (enforceMode === 'enforce') {
        res.status(402).json(viralResponse);
        return;
      } else {
        // Audit mode: let it pass through unverified
        req.repuwave = undefined;
        next();
        return;
      }
    }

    try {
      const result: VerificationResult = await client.verify(uaid);

      // Attach to request for downstream handlers
      req.repuwave = result;

      // Cryptographic Signature Check (Option B)
      const signature = req.headers["x-repuwave-signature"] as string | undefined;
      const timestampStr = req.headers["x-repuwave-timestamp"] as string | undefined;

      if (signature && timestampStr && result.public_key) {
        try {
          const crypto = require("crypto");
          const timestamp = parseFloat(timestampStr);
          const now = Date.now() / 1000;
          
          if (Math.abs(now - timestamp) > 15.0) {
            res.status(403).json({
              error: "Trust Window Expired",
              message: "Timestamp outside 15s trust window",
            });
            return;
          }

          let bodyHash = "";
          if (req.body && Object.keys(req.body).length > 0) {
            // Best effort body stringification. For true exact matching,
            // services should use raw body middleware.
            const bodyString = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
            bodyHash = crypto.createHash("sha256").update(bodyString).digest("hex");
          }

          const payload = {
            body_hash: bodyHash,
            timestamp: timestamp,
            uaid: uaid,
          };

          const sortedKeys = Object.keys(payload).sort() as (keyof typeof payload)[];
          const orderedPayload: Record<string, any> = {};
          for (const key of sortedKeys) {
            orderedPayload[key] = payload[key];
          }
          const canonicalPayload = JSON.stringify(orderedPayload);
          const payloadHash = crypto.createHash("sha256").update(canonicalPayload).digest();

          // Construct DER-encoded SPKI public key from the 32-byte hex key
          const pubKeyBytes = Buffer.from(result.public_key, "hex");
          const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
          const spkiDer = Buffer.concat([spkiPrefix, pubKeyBytes]);
          const publicKeyObj = {
            key: spkiDer,
            format: "der" as const,
            type: "spki" as const,
          };

          const isValid = crypto.verify(null, payloadHash, publicKeyObj, Buffer.from(signature, "hex"));
          if (!isValid) {
            res.status(403).json({
              error: "Signature Mismatch",
              message: "Invalid agent signature",
            });
            return;
          }
        } catch (err: any) {
          res.status(400).json({
            error: "Invalid Signature Format",
            message: String(err.message || err),
          });
          return;
        }
      }

      // Check if agent meets minimum score
      if (!result.verified || result.score < minScore) {
        if (enforceMode === 'enforce') {
          res.status(402).json(viralResponse);
          return;
        }
      }

      next();
    } catch (err: any) {
      // On API failure, let the request through (fail-open)
      // but log the error. Override with fail-closed if needed.
      console.error("[repuwave] Verification error:", err.message);
      next();
    }
  };
}
