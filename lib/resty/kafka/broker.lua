-- Copyright (C) Dejiang Zhu(doujiang24)


local response = require "resty.kafka.response"
local request = require "resty.kafka.request"


local to_int32 = response.to_int32
local setmetatable = setmetatable
local rshift = bit.rshift
local band = bit.band
local char = string.char
local ngx_log = ngx.log
local tcp = ngx.socket.tcp
local pid = ngx.worker.pid


local _M = {}
local mt = { __index = _M }


local function _send_receive(sock, payload)
    ngx.log(ngx.DEBUG, "==> _send_receive()")
    logger:log(ngx.DEBUG, "==> _send_receive()")
    local bytes, err = sock:send(payload)
    ngx.log(ngx.DEBUG, "==> bytes: ", bytes, ", err: ", err)
    logger:log(ngx.DEBUG, "==> bytes: ", bytes, ", err: ", err)
    if not bytes then
        return nil, err, true
    end

    local data, err = sock:receive(4)
    ngx.log(ngx.DEBUG, "==> sock:receive(4) err: ", err)
    logger:log(ngx.DEBUG, "==> sock:receive(4) data: ", data, ", err: ", err)
    if not data then
        if err == "timeout" then
            sock:close()
            return nil, err
        end
        return nil, err, true
    end

    local len = to_int32(data)
    logger:log(ngx.DEBUG, "==> to_int32(data) len: ", len)

    local data, err = sock:receive(len)
    ngx.log(ngx.DEBUG, "==> sock:receive(len) err: ", err)
    logger:log(ngx.DEBUG, "==> sock:receive(len) data: ", data, ", err: ", err)
    if not data then
        if err == "timeout" then
            sock:close()
            return nil, err
        end
        return nil, err, true
    end

    if data == "" then -- send authBytes has no response
        logger:log(ngx.DEBUG, "==> _send_receive() return true as authBytes resp")
        return true
    else
        logger:log(ngx.DEBUG, "==> _send_receive() return resp, nil and true")
        return response:new(data), nil, true
    end
end


function _M.new(self, host, port, socket_config)
    logger:log(ngx.DEBUG, "==> +++++ new a broker as agent... +++++ ")
    return setmetatable({
        host = host,
        port = port,
        config = socket_config,
    }, mt)
end


local function sasl_plain_handshake(sock)
    logger:log(ngx.DEBUG, "==> kafka sals plain handshake")
    local id = 0    -- hard code correlation_id
    local client_id = "worker" .. pid()
    local req = request:new(request.SaslHandshakeRequest, id, client_id)

    req:string("PLAIN")

    local resp, err, retryable = _send_receive(sock, req:package())
    if resp then
        if resp:int16() == 0 and resp:int32() == 1 and resp:string() == "PLAIN" then
            return true
        else
            return nil, "sasl_plain not available"
        end
    else
        ngx_log(ngx.ERR, "sasl plain handshake failed!")
        return nil, err
    end
end


-- copy from file request.lua
local function str_int32(int)
    -- ngx.say(debug.traceback())
    return char(band(rshift(int, 24), 0xff),
                band(rshift(int, 16), 0xff),
                band(rshift(int, 8), 0xff),
                band(int, 0xff))
end


local function sasl_plain_auth(sock, config)
    logger:log(ngx.DEBUG, "==> kafka sals plain auth with config: ", config)
    local ok, err = sasl_plain_handshake(sock)
    if not ok then
        return nil, err
    end

    -- https://kafka.apache.org/protocol.html#sasl_handshake
    -- credentials are sent as 'opaque packets'
    -- so it should be bytes primitive uses an int32.
    -- https://github.com/Shopify/sarama/blob/0f4f8caef994ca7e4f9072c1858b7c6761ed498f/broker.go#L667
    local password
    if type(config.password) == "function" then
        password = config.password()
    else
        password = config.password
    end
    local length = 1 + #config.username + 1 + #password
    local payload = table.concat({'\0', config.username, '\0', password})
    local authBytes = {str_int32(length), payload}

    -- if auth failed, kafka server will close socket
    -- return nil, closed
    return _send_receive(sock, authBytes)
end


function _M.send_receive(self, req)
    ngx.log(ngx.DEBUG, "==> broker:send_receive()")
    logger:log(ngx.DEBUG, "==> broker:send_receive()")
    local sock, err = tcp()
    if not sock then
        ngx.log(ngx.DEBUG, "==> broker:send_receive() not sock")
        return nil, err, true
    end
    logger:log(ngx.DEBUG, "==> broker:send_receive() new a tcpsocket")
    sock:settimeout(self.config.socket_timeout)

    local ok, err = sock:connect(self.host, self.port)
    if not ok then
        ngx.log(ngx.DEBUG, "==> broker:send_receive() sock:connect ok: ", ok)
        return nil, err, true
    end

    ngx.log(ngx.DEBUG, "==> sock:getreusedtimes() returns: ", sock:getreusedtimes())
    logger:log(ngx.DEBUG, "==> sock:getreusedtimes() returns: ", sock:getreusedtimes())
    if sock:getreusedtimes() == 0 and self.config.sasl_enable then
        local ok, err = sasl_plain_auth(sock, self.config)
        if not ok then
            return nil, err
        end
        logger:log(ngx.DEBUG, "==> kafka sals plain auth done!")
    end

    ngx.log(ngx.DEBUG, "==> broker:send_receive() call _send_receive()")
    logger:log(ngx.DEBUG, "==> broker:send_receive() call _send_receive()")
    local resp, err, retryable = _send_receive(sock, req:package())
    ngx.log(ngx.DEBUG, "==> broker:send_receive() call _send_receive() err: ", err)

    logger:log(ngx.DEBUG, "==> sock:setkeepalive")
    sock:setkeepalive(self.config.keepalive_timeout, self.config.keepalive_size)

    return resp, err, retryable
end


return _M
