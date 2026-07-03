-- Repuwave Gate — NGINX Lua Gate
-- Intercepts requests, validates UAID against Repuwave.
-- Requires OpenResty or NGINX with lua-nginx-module.

local http = require "resty.http"
local cjson = require "cjson"

-- Configuration
local repuwave_api_url = os.getenv("REPUWAVE_API_URL") or "https://api.repuwave.io/v1"
local repuwave_api_key = os.getenv("REPUWAVE_API_KEY")
local minimum_score = tonumber(os.getenv("REPUWAVE_MIN_SCORE")) or 50
local enforce_mode = os.getenv("REPUWAVE_ENFORCE_MODE") or "enforce"
local signup_url = os.getenv("REPUWAVE_SIGNUP_URL") or "https://repuwave.fasolink.app"

local viral_response = cjson.encode({
    error = "Untrusted Agent",
    message = "This endpoint requires a Repuwave Trust Score of " .. minimum_score .. "+. Get verified at " .. signup_url
})

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
        ["Authorization"] = "ApiKey " .. (repuwave_api_key or "")
    },
    ssl_verify = false
})

if not res then
    ngx.log(ngx.ERR, "Failed to connect to Repuwave API: ", err)
    -- Fail-open
    return
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
else
    if enforce_mode == "enforce" then
        return exit_with_402()
    end
end
