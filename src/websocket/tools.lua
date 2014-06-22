local struct = require'struct'
local socket = require'socket'
local bit = require'websocket.bit'
local rol = bit.rol
local bxor = bit.bxor
local bor = bit.bor
local band = bit.band
local bnot = bit.bnot
local lshift = bit.lshift
local rshift = bit.rshift
local sunpack = string.unpack
local srep = string.rep
local schar = string.char
local tremove = table.remove
local tinsert = table.insert
local tconcat = table.concat
local mrandom = math.random

-- used for generate key random ops
math.randomseed(os.time())

-- from wiki article, not particularly clever impl
local sha1 = function(msg)
  local crypto = require'crypto'
  return crypto.digest('sha1',msg,true)
end

local base64_encode = function(data)
  local mime = require'mime'
  return (mime.b64(data))
end

local parse_url = function(url)
  local protocol,host = url:match('^(%w+)://([^:/]+)')
  local port,uri = url:match('.+//[^:/]+:?(%d*)(.*)')
  if port and port ~= '' then
    port = tonumber(port)
  elseif protocol == 'ws' then
    port = 80
  end
  if not uri or uri == '' then
    uri = '/'
  end
  if not protocol or not host or not port or not uri then
    error('Invalid URL:'..url)
  end
  return protocol,host,port,uri
end

local generate_key = function()
  local r1 = mrandom(0,0xfffffff)
  local r2 = mrandom(0,0xfffffff)
  local r3 = mrandom(0,0xfffffff)
  local r4 = mrandom(0,0xfffffff)
  local key = struct.pack('IIII',r1,r2,r3,r4)
  assert(#key==16,#key)
  return base64_encode(key)
end

local bind = function(host,port)
  if socket.tcp6 then
    local server = socket.tcp6()
    local _,err = server:setoption('ipv6-v6only',false)
    if err then
      server:close()
      return nil,err
    end
    _,err = server:setoption("reuseaddr", true)
    if err then
      server:close()
      return nil,err
    end
    _,err = server:bind(host,port)
    if err then
      server:close()
      return nil,err
    end
    _,err = server:listen()
    if err then
      server:close()
      return nil,err
    end
    return server
  else
    return socket.bind(host,port)
  end
end

return {
  sha1 = sha1,
  base64 = {
    encode = base64_encode
  },
  parse_url = parse_url,
  generate_key = generate_key,
  bind = bind,
}
