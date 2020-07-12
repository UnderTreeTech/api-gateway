--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local core     = require("apisix.core")
local jwt      = require("resty.jwt")
local ck       = require("resty.cookie")
local sub_str  = string.sub
local plugin_name = "jwt"

local schema = {
    type = "object",
    properties = {
        appkey = {type = "string",minLength = 4,maxLength = 16,pattern = [[^[a-zA-Z0-9_-]{4,16}$]]},
        secret = {type = "string"},
        algorithm = {
            type = "string",
            enum = {"HS256", "HS384", "HS512", "RS256", "ES256"}
        },
        exp = {type = "integer", minimum = 1}
    },
    required = {"appkey", "secret", "exp", "algorithm"}
}

local _M = {
    version = 0.1,
    priority = 2512,
    type = 'auth',
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end

    if not conf.algorithm then
        conf.algorithm = "HS256"
    end

    if not conf.exp then
        conf.exp = 60 * 60 * 24
    end

    return true
end

local function fetch_jwt_token(ctx)
    local token = core.request.header(ctx, "authorization")
    if token then
        local prefix = sub_str(token, 1, 7)
        if prefix == 'Bearer ' or prefix == 'bearer ' then
            return sub_str(token, 8)
        end
        return token
    end

    token = ctx.var.arg_jwt
    if token then
        return token
    end

    local cookie, err = ck:new()
    if not cookie then
        return nil, err
    end

    local val, err = cookie:get("jwt")
    return val, err
end

function _M.rewrite(conf, ctx)
    core.log.info("conf info: ",
            core.json.delay_encode(ctx.var, true))
    core.log.info("args: ",ngx.var.args)
    local appkey = core.request.header(ctx, "appkey")
    if conf.appkey ~= appkey then
        return 401 , {code = 100000,message = "invalid appkey"}
    end

    local jwt_token, err = fetch_jwt_token(ctx)
    if not jwt_token then
        if err and err:sub(1, #"no cookie") ~= "no cookie" then
            core.log.error("failed to fetch JWT token: ", err)
        end

        return 401, {code = 100000,message = "Missing JWT token in request"}
    end

    local jwt_obj = jwt:load_jwt(jwt_token)
    core.log.info("jwt object: ", core.json.delay_encode(jwt_obj))
    if not jwt_obj.valid then
        return 401, {code = 100000,message = jwt_obj.reason}
    end

    local auth_secret = conf.secret
    jwt_obj = jwt:verify_jwt_obj(auth_secret, jwt_obj)
    core.log.info("jwt object: ", core.json.delay_encode(jwt_obj))
    if not jwt_obj.verified then
        return 401, {code = 100000,message = jwt_obj.reason}
    else
        return 401, {code = 100000,message = core.json.encode(jwt_obj)}
    end

    core.log.info("hit customer jwt authorization rewrite")
end

return _M
