require'pack'
local socket = require'socket'
local bit = require'websocket.bit'
local rol = bit.rol
local bxor = bit.bxor
local bor = bit.bor
local band = bit.band
local bnot = bit.bnot
local lshift = bit.lshift
local rshift = bit.rshift
local spack = string.pack
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

local base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

-- from wiki article, not particularly clever impl
local base64_encode = function(data)
  local result = ''
  local padding = ''
  local count = #data % 3
  
  if count > 0 then
    for i=count,2 do
      padding = padding..'='
      data = data..'\0'
    end
  end
  assert(#data % 3 == 0,#data % 3)
  local bytes = 0
  for i=1,#data,3 do
    local chars = {data:sub(i,i+2):byte(1,3)}
    assert(#chars==3,#chars)
    local n = lshift(chars[1],16) + lshift(chars[2],8) + chars[3]
    local narr = {}
    narr[1] = band(rshift(n,18),63)+1
    narr[2] = band(rshift(n,12),63)+1
    narr[3] = band(rshift(n,6),63)+1
    narr[4] = band(n,63)+1
    result = result..base64chars:sub(narr[1],narr[1])
    result = result..base64chars:sub(narr[2],narr[2])
    result = result..base64chars:sub(narr[3],narr[3])
    result = result..base64chars:sub(narr[4],narr[4])
  end
  return result:sub(1,#result-#padding)..padding
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
  local key = spack('IIII',r1,r2,r3,r4)
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
