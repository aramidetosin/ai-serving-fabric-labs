--
-- oidc-consumer: an APISIX authentication plugin that maps a caller's OpenID Connect token onto
-- a consumer, so a person signed in to the identity provider is a consumer as an application
-- holding a key is one (consumer groups, consumer restriction, rate limits and logs then treat
-- both alike). The lab's API gateway runs it beside key-auth under multi-auth.
--
-- APISIX 3.9's own plugins do not do this: openid-connect verifies a bearer token but attaches
-- no consumer (and with a public key or JWKS checks no issuer or audience), and jwt-auth finds
-- its consumer by a `key` claim an identity provider does not issue. This plugin uses the
-- libraries APISIX ships for openid-connect (lua-resty-openidc and lua-resty-jwt) to check the
-- signature against the provider's published keys (RS256 only; a key id it has not seen makes it
-- read the key set again), then checks the claims itself:
--   exp and nbf      lua-resty-jwt's own checks, with iat_slack seconds of leeway
--   iss              equal to the configured issuer
--   aud              equal to, or a list holding, the configured audience: the API gateway's own
--                    client id, which the provider writes into a token only when the requesting
--                    client asked for it and the API gateway trusts that client
--   the subject      the configured claim (email by default) present, and, for email,
--                    email_verified true
-- and attaches the consumer whose oidc-consumer subject equals that claim. Every refusal is 401
-- with one message, so a caller learns nothing about which check failed. A verified token is
-- never cached across configurations (jwt_verification_cache_ignore), so a token one route
-- accepted is checked again by another.
--
-- Route configuration:  {issuer, jwks_uri, audience, claim?, timeout_s?, jwk_expires_in?, hide_credentials?}
-- Consumer:             {subject}
--
local core         = require("apisix.core")
local consumer_mod = require("apisix.consumer")
local openidc      = require("resty.openidc")
local ngx_re       = require("ngx.re")
local type         = type
local ipairs       = ipairs
local tostring     = tostring

local plugin_name = "oidc-consumer"
local REFUSED = "Authorization Failed"

local schema = {
    type = "object",
    properties = {
        issuer = {type = "string", minLength = 1},
        jwks_uri = {type = "string", minLength = 1},
        audience = {type = "string", minLength = 1},
        claim = {type = "string", default = "email"},
        timeout_s = {type = "integer", minimum = 1, default = 3},
        jwk_expires_in = {type = "integer", minimum = 1, default = 300},
        iat_slack = {type = "integer", minimum = 0, default = 60},
        hide_credentials = {type = "boolean", default = true},
    },
    required = {"issuer", "jwks_uri", "audience"},
}

local consumer_schema = {
    type = "object",
    properties = {
        subject = {type = "string", minLength = 1},
    },
    required = {"subject"},
}

local _M = {
    version = 0.1,
    priority = 2505,
    type = "auth",
    name = plugin_name,
    schema = schema,
    consumer_schema = consumer_schema,
}


function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_CONSUMER then
        return core.schema.check(consumer_schema, conf)
    end
    return core.schema.check(schema, conf)
end


local function bearer(ctx)
    local h = core.request.header(ctx, "Authorization")
    if not h then
        return nil
    end
    local m = ngx_re.split(h, " ", nil, nil, 2)
    if not m or #m ~= 2 or m[1]:lower() ~= "bearer" or m[2] == "" then
        return nil
    end
    return m[2]
end


local function has_audience(aud, want)
    if type(aud) == "string" then
        return aud == want
    end
    if type(aud) == "table" then
        for _, a in ipairs(aud) do
            if a == want then
                return true
            end
        end
    end
    return false
end


-- multi-auth calls rewrite with the configuration as written, never through the schema, so the
-- defaults are applied here too
local DEFAULTS = {claim = "email", timeout_s = 3, jwk_expires_in = 300, iat_slack = 60, hide_credentials = true}

local function setting(conf, k)
    if conf[k] == nil then
        return DEFAULTS[k]
    end
    return conf[k]
end


function _M.rewrite(conf, ctx)
    local token = bearer(ctx)
    -- a key (sk-...) is not a JWT: three dot-separated parts are the least a token has
    if not token or not token:find("^[%w_-]+%.[%w_-]+%.[%w_-]+$") then
        return 401, {message = REFUSED}
    end
    local opts = {
        discovery = {issuer = conf.issuer, jwks_uri = conf.jwks_uri},
        token_signing_alg_values_expected = {"RS256"},
        accept_none_alg = false,
        jwt_verification_cache_ignore = true,
        jwk_expires_in = setting(conf, "jwk_expires_in"),
        timeout = setting(conf, "timeout_s") * 1000,
        iat_slack = setting(conf, "iat_slack"),
        ssl_verify = "yes",
    }
    local claims, err = openidc.jwt_verify(token, opts)
    if err or type(claims) ~= "table" then
        core.log.warn("oidc-consumer: token refused: ", err or "no claims")
        return 401, {message = REFUSED}
    end
    if claims.iss ~= conf.issuer then
        core.log.warn("oidc-consumer: token refused: issuer ", tostring(claims.iss))
        return 401, {message = REFUSED}
    end
    if not has_audience(claims.aud, conf.audience) then
        core.log.warn("oidc-consumer: token refused: the audience does not name ", conf.audience)
        return 401, {message = REFUSED}
    end
    local claim = setting(conf, "claim")
    local subject = claims[claim]
    if type(subject) ~= "string" or subject == "" or (claim == "email" and claims.email_verified ~= true) then
        core.log.warn("oidc-consumer: token refused: no verified ", claim)
        return 401, {message = REFUSED}
    end
    local consumer_conf = consumer_mod.plugin(plugin_name)
    if not consumer_conf then
        return 401, {message = REFUSED}
    end
    local consumers = consumer_mod.consumers_kv(plugin_name, consumer_conf, "subject")
    local consumer = consumers[subject]
    if not consumer then
        core.log.warn("oidc-consumer: token refused: no consumer for the subject")
        return 401, {message = REFUSED}
    end
    if setting(conf, "hide_credentials") then
        core.request.set_header(ctx, "Authorization", nil)
    end
    consumer_mod.attach_consumer(ctx, consumer, consumer_conf)
end


return _M
