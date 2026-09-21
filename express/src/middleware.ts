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
 *     apiUrl: "https://repuwave.fasolink.app/v1",
 *     apiKey: process.env.REPUWAVE_API_KEY!,
 *     minimumScore: 60,
 *   }));
 */

import type { Request, Response, NextFunction } from "express";
import { REPUWAVE_DEFAULTS } from "./types";
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
    const enforceMode = config.enforceMode ?? REPUWAVE_DEFAULTS.enforceMode;
    const signupUrl = config.signupUrl ?? REPUWAVE_DEFAULTS.signupUrl;
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

    // Read the agent's proof before calling out. The server checks the
    // signature itself and refuses without it -- a UAID alone proves nothing,
    // because UAIDs are public in the key directory -- so it has to be
    // forwarded, and the body hash with it, since only we saw the body.
    const signature = req.headers["x-repuwave-signature"] as string | undefined;
    const timestampStr = req.headers["x-repuwave-timestamp"] as string | undefined;

    const crypto = require("crypto");
    let bodyHash = "";
    if (req.body && Object.keys(req.body).length > 0) {
      // Best effort body stringification. For true exact matching,
      // services should use raw body middleware.
      const bodyString =
        typeof req.body === "string" ? req.body : JSON.stringify(req.body);
      bodyHash = crypto.createHash("sha256").update(bodyString).digest("hex");
    }

    try {
      const result: VerificationResult = await client.verify(uaid, {
        signature,
        timestamp: timestampStr,
        bodyHash,
      });

      // Attach to request for downstream handlers
      req.repuwave = result;

      // Cryptographic Signature Check (Option B). Kept as well as the
      // server-side check: it costs nothing here and a second, independent
      // verification is the difference between one bug and two.
      // Unconditional when a public key came back.
      //
      // This used to read `if (signature && timestampStr && result.public_key)`,
      // so an attacker who simply omitted the signature skipped the local check
      // entirely -- the same `if signature and timestamp` anti-pattern the
      // Python guards removed. A caller does not get to choose whether they are
      // checked.
      if (result.public_key) {
        if (!signature || !timestampStr) {
          if (enforceMode === 'enforce') {
            res.status(403).json({
              error: "Signature Required",
              message:
                "This endpoint requires a signed request. Send X-Repuwave-Signature " +
                "and X-Repuwave-Timestamp alongside your UAID.",
            });
            return;
          }
          next();
          return;
        }
        try {
          const timestamp = parseFloat(timestampStr);
          const now = Date.now() / 1000;
          
          if (Math.abs(now - timestamp) > 15.0) {
            res.status(403).json({
              error: "Trust Window Expired",
              message: "Timestamp outside 15s trust window",
            });
            return;
          }

          // Render the timestamp exactly as Python's json.dumps does — it
          // always keeps a decimal point (e.g. 1700000000.0), whereas JS
          // drops the trailing ".0" for whole seconds. Without this, a
          // whole-second timestamp produces a different canonical string
          // and verification fails. Build the string manually so the
          // number formatting is preserved.
          const tsRaw = timestampStr.trim();
          const timestampStrCanonical = /[.eE]/.test(tsRaw) ? tsRaw : `${tsRaw}.0`;
          const canonicalPayload =
            `{"body_hash":${JSON.stringify(bodyHash)},` +
            `"timestamp":${timestampStrCanonical},` +
            `"uaid":${JSON.stringify(uaid)}}`;
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
      // Failure mode is a deliberate choice now, and it defaults to closed.
      //
      // It used to be an unconditional fail-open documented only in this
      // comment. That was defensible while this path meant "Repuwave is down".
      // Since 21 Sep 2026 GET /v1/verify/ requires the agent's signature, so an
      // ordinary unsigned request arrives here as a 401 -- and fail-open turned
      // the guard into something anyone could walk past by deleting one header.
      console.error("[repuwave] Verification error:", err.message);

      if ((config.failureMode ?? REPUWAVE_DEFAULTS.failureMode) === 'open') {
        next();
        return;
      }

      // 502, not 402. The agent is not untrusted -- we could not find out.
      // Telling its developer to go improve their reputation would send them to
      // fix something that is not broken.
      res.status(502).json({
        error: "Verification Unavailable",
        message:
          "Could not verify agent reputation. This is a problem at the gateway, " +
          "not with your agent.",
      });
    }
  };
}
