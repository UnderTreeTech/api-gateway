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
local ngx      = ngx
local md5      = ngx.md5
local encode_args = ngx.encode_args
local tonumber = tonumber
local plugin_name = "signature"

local schema = {
    type = "object",
    properties = {
        appkey = {type = "string",minLength = 4,maxLength = 16,pattern = [[^[a-zA-Z0-9_-]{4,16}$]]},
        secret = {type = "string"},
        algorithm = {
            type = "string",
            enum = {"md5"},
            default = "md5"
        },
        timeout = {type = "integer", minimum = 10, default = 10}
    },
    required = {"appkey", "secret", "timeout", "algorithm"}
}

local _M = {
    version = 0.1,
    priority = 2513,
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
        conf.algorithm = "md5"
    end

    if not conf.timeout then
        conf.timeout = 10
    end

    return true
end

local function get_args(action)
    local args
    if action ~= "GET" then
        ngx.req.read_body()
        local json_body = ngx.req.get_body_data()
        if "nil" == type(json_body) then
            json_body = ""
        end
        args = json_body
    else
        local query_params = ngx.req.get_uri_args()
        local encode_query = encode_args(query_params)
        args = encode_query
    end

    core.log.info("request original args is: ",args)
    return args
end

function _M.rewrite(conf, ctx)
    local args = get_args(ctx.var.request_method)

    -- check appkey
    local appkey = core.request.header(ctx, "appkey")
    if conf.appkey ~= appkey then
        return 400, {code = 100000,message = "应用程序不存在或已被封禁"}
    end

    -- check request timeout
    local timestamp = core.request.header(ctx,"timestamp")
    local ts = tonumber(timestamp)
    if "nil" == ts then
        return 400, {code = 100000, message = "wrong timestamp"}
    end

    local now = ngx.time()
    if math.abs(now - timestamp) > conf.timeout then
        core.log.info("request timeout, current time is ", now," ,request time is ",timestamp," timeout conf is ",conf.timeout)
        return 400, {code = 100000, message = "请求超时"}
    end

    -- check signature
    local unsign_text = args .. timestamp .. conf.secret
    core.log.info("unsign text is: ", unsign_text)
    local calculate_sign = md5(unsign_text)
    local request_sign = core.request.header(ctx,"sign")
    if request_sign ~= calculate_sign then
        core.log.info("check sign fail, request sign is ", request_sign," ,calculate sign is ",calculate_sign)
        return 400, {code = 100000, message = "非法请求，签名错误"}
    end

    core.log.info("hit customer signature authorization rewrite")
end

return _M
