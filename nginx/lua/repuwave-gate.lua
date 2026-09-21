-- Repuwave Gate — NGINX Lua Gate
-- Intercepts requests, validates UAID against Repuwave.
-- Requires OpenResty or NGINX with lua-nginx-module.

local http = require "resty.http"
local cjson = require "cjson"

-- Configuration
local repuwave_api_url = os.getenv("REPUWAVE_API_URL") or "https://repuwave.fasolink.app/v1"
local repuwave_api_key = os.getenv("REPUWAVE_API_KEY")
local minimum_score = tonumber(os.getenv("REPUWAVE_MIN_SCORE")) or 50
local enforce_mode = os.getenv("REPUWAVE_ENFORCE_MODE") or "enforce"
local signup_url = os.getenv("REPUWAVE_SIGNUP_URL") or "https://repuwave.fasolink.app"

-- What to do when Repuwave itself cannot be reached.
--
-- This is a real decision with no free answer, so it is explicit rather than
-- implied. "closed" means an outage at Repuwave blocks agent traffic to your
-- API. "open" means an outage at Repuwave silently removes the protection this
-- gate exists to provide, and nothing in the response says so.
--
-- The default follows the mode name: a gate configured to enforce should
-- enforce, including when it cannot check. Set REPUWAVE_FAIL_MODE=open if
-- availability matters more to you than the check -- but choose it, rather than
-- inheriting it from an error path.
local fail_mode = os.getenv("REPUWAVE_FAIL_MODE") or "closed"

-- Clear the headers this gate sets, before doing anything else.
--
-- The gate sets X-Repuwave-Score and X-Repuwave-Verified for the backend on the
-- success path. Every other path -- audit mode with no UAID, a transport error,
-- a 401/403 from Repuwave -- left whatever the client sent in place, and the
-- backend had no way to tell a gate-set value from a forged one. A client could
-- simply send "X-Repuwave-Score: 100".
--
-- repuwave.conf already performs exactly this hygiene for X-JA3-Fingerprint and
-- explains why it is necessary. The same reasoning applies here and was not
-- applied. Unconditional, at the top, so no later branch can forget.
ngx.req.clear_header("X-Repuwave-Score")
ngx.req.clear_header("X-Repuwave-Verified")

local viral_response = cjson.encode({
    error = "Untrusted Agent",
    message = "This endpoint requires a Repuwave Trust Score of " .. minimum_score .. "+. Get verified at " .. signup_url
})

-- Distinct from 402. A 402 tells the caller their agent is untrusted, which is
-- a statement about them; if Repuwave is unreachable we do not know that and
-- must not imply it. 502 says the gate could not complete its check.
local function exit_with_502()
    ngx.status = 502
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode({
        error = "Trust check unavailable",
        message = "The Repuwave trust API could not be reached, and this gate is "
            .. "configured to fail closed. Set REPUWAVE_FAIL_MODE=open to allow "
            .. "traffic through during an outage."
    }))
    return ngx.exit(502)
end

local function exit_with_402()
    ngx.status = 402
    ngx.header.content_type = "application/json"
    ngx.say(viral_response)
    return ngx.exit(402)
end

local uaid = ngx.req.get_headers()["X-Repuwave-UAID"]

if not uaid then
    if enforce_mode == "enforce" then
        return exit_with_402()
    else
        -- Audit mode: pass through
        return
    end
end

-- Make API call to Repuwave
local httpc = http.new()
local res, err = httpc:request_uri(repuwave_api_url .. "/verify/" .. uaid .. "/", {
    method = "GET",
    headers = {
        -- X-Service-API-Key, not Authorization. The server reads
        -- HTTP_X_SERVICE_API_KEY (apps/gateway/permissions/service.py), so the
        -- previous "Authorization: ApiKey ..." was rejected with 403 on every
        -- single call. In enforce mode that meant 402 for all legitimate
        -- traffic; in audit mode it meant the gate checked nothing at all.
        ["X-Service-API-Key"] = repuwave_api_key or "",
        -- Forward the agent's own proof. The server verifies the signature and
        -- refuses without it: a UAID alone proves nothing, because UAIDs are
        -- public in the key directory. Reading the request body here would
        -- require ngx.req.read_body() on every request, so the body hash is
        -- forwarded only if the agent's client sent it as a header -- this gate
        -- is for bodyless GET traffic, and a request with a body should use one
        -- of the application-level middlewares instead.
        ["X-Repuwave-Signature"] = ngx.var.http_x_repuwave_signature or "",
        ["X-Repuwave-Timestamp"] = ngx.var.http_x_repuwave_timestamp or "",
        ["X-Repuwave-Body-Hash"] = ngx.var.http_x_repuwave_body_hash or ""
    },
    -- TLS verification ON. This was false, which disabled certificate checking
    -- on the one request whose answer is a security decision -- anyone able to
    -- intercept it could return a score of 100.
    ssl_verify = true
})

if not res then
    ngx.log(ngx.ERR, "Repuwave API unreachable: ", err, " (fail_mode=", fail_mode, ")")
    if fail_mode == "open" then
        return
    end
    return exit_with_502()
end

if res.status == 200 then
    local data = cjson.decode(res.body)
    
    -- Inject downstream headers if needed
    ngx.req.set_header("X-Repuwave-Score", tostring(data.score))
    ngx.req.set_header("X-Repuwave-Verified", tostring(data.verified))
    
    if not data.verified or (data.score or 0) < minimum_score then
        if enforce_mode == "enforce" then
            return exit_with_402()
        end
    end
elseif res.status == 401 or res.status == 403 then
    -- The gate's own credential is wrong, not the agent's. Answering 402 here
    -- would tell every caller their agent is untrusted when the truth is that
    -- this gate is misconfigured -- which is how a wrong header went unnoticed:
    -- the symptom looked like working enforcement.
    ngx.log(ngx.ERR,
        "Repuwave rejected the gate's own API key (HTTP ", res.status,
        "). Check REPUWAVE_API_KEY. This is a gate misconfiguration, not an ",
        "untrusted agent.")
    if fail_mode == "open" then
        return
    end
    return exit_with_502()
else
    ngx.log(ngx.ERR, "Unexpected response from Repuwave API: HTTP ", res.status)
    if enforce_mode == "enforce" then
        return exit_with_402()
    end
end
