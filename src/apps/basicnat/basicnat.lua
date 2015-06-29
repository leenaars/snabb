module(..., package.seeall)

local bit = require("bit")
local pf = require("pf")

--- ### `basicnat` app: Implement http://www.ietf.org/rfc/rfc1631.txt Basic NAT
--- This translates one IP address to another IP address

BasicNAT = {}

local function bytes_to_uint32(a, b, c, d)
   return a * 2^24 + b * 2^16 + c * 2^8 + d
end

local function str_ip_to_uint32(ip)
   local a, b, c, d = ip:match("([0-9]+).([0-9]+).([0-9]+).([0-9]+)")
   return bytes_to_uint32(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
end

local function subst(str, values)
   local out, pos = '', 1
   while true do
      local before, after = str:match('()%$[%w_]+()', pos)
      if not before then return out..str:sub(pos) end
      out = out..str:sub(pos, before - 1)
      local var = str:sub(before + 1, after - 1)
      local val = values[var]
      print (before, after, var, val)
      if not val then error('var not found: '..var) end
      out = out..val
      pos = after
   end
   return out
end

local ipv4_base = 14 -- Ethernet encapsulated ipv4
local transport_base = 34 -- tranport layer (TCP/UDP/etc) header start
local proto_tcp = 6
local proto_udp = 17

local function uint32_to_bytes(u)
   local a = bit.rshift(u, 24)
   local b = bit.band(bit.rshift(u, 16), 0xff)
   local c = bit.band(bit.rshift(u, 8), 0xff)
   local d = bit.band(u, 0xff)
   return a, b, c, d
end

local function csum_carry_and_not(checksum)
   while checksum > 0xffff do -- process the carry nibbles
      local carry = bit.rshift(checksum, 16)
      checksum = bit.band(checksum, 0xffff) + carry
   end
   return bit.band(bit.bnot(checksum), 0xffff)
end

local function ipv4_checksum(pkt)
   local checksum = 0
   for i = ipv4_base, ipv4_base + 18, 2 do
      if i ~= ipv4_base + 10 then -- The checksum bytes are assumed to be 0
         checksum = checksum + pkt.data[i] * 0x100 + pkt.data[i+1]
      end
   end
   return csum_carry_and_not(checksum)
end

local function transport_checksum(pkt)
   local checksum = 0
   -- First 64 bytes of the TCP pseudo-header: the ip addresses
   for i = ipv4_base + 12, ipv4_base + 18, 2 do
      checksum = checksum + pkt.data[i] * 0x100 + pkt.data[i+1]
   end
   -- Add the protocol field of the IPv4 header to the checksum
   local protocol = pkt.data[ipv4_base + 9]
   checksum = checksum + protocol
   local tcplen = pkt.data[ipv4_base + 2] * 0x100 + pkt.data[ipv4_base + 3] - 20
   checksum = checksum + tcplen -- end of pseudo-header

   for i = transport_base, transport_base + tcplen - 2, 2 do
      if i ~= transport_base + 16 then -- The checksum bytes are zero
         checksum = checksum + pkt.data[i] * 0x100 + pkt.data[i+1]
      end
   end
   if tcplen % 2 == 1 then
      checksum = checksum + pkt.data[transport_base + tcplen - 1]
   end
   return csum_carry_and_not(checksum)
end

local function fix_checksums(pkt, len)
   local ipchecksum = ipv4_checksum(pkt)
   pkt.data[ipv4_base + 10] = bit.rshift(ipchecksum, 8)
   pkt.data[ipv4_base + 11] = bit.band(ipchecksum, 0xff)
   local transport_proto = pkt.data[ipv4_base + 9]
   if transport_proto == proto_tcp then
      local transport_csum = transport_checksum(pkt)
      pkt.data[transport_base + 16] = bit.rshift(transport_csum, 8)
      pkt.data[transport_base + 17] = bit.band(transport_csum, 0xff)
      return true
   elseif transport_proto == proto_udp then
      -- ipv4 udp checksums are optional
      pkt.data[transport_base + 6] = 0
      pkt.data[transport_base + 7] = 0
      return true
   else
      return false -- didn't attempt to change a transport-layer checksum
   end
end

-- TODO: fix the checksum
local function set_src_ip(pkt, len, ip)
   local a, b, c, d = uint32_to_bytes(ip)
   pkt.data[ipv4_base + 12] = a
   pkt.data[ipv4_base + 13] = b
   pkt.data[ipv4_base + 14] = c
   pkt.data[ipv4_base + 15] = d
   return pkt
end

-- TODO: fix the checksum
local function set_dst_ip(pkt, len, ip)
   local a, b, c, d = uint32_to_bytes(ip)
   pkt.data[ipv4_base + 16] = a
   pkt.data[ipv4_base + 17] = b
   pkt.data[ipv4_base + 18] = c
   pkt.data[ipv4_base + 19] = d
   return pkt
end

-- For packets outbound from the
-- private IP, the source IP address and related fields such as IP,
-- TCP, UDP and ICMP header checksums are translated. For inbound
-- packets, the destination IP address and the checksums as listed above
-- are translated.

-- FIXME: Would be nice to have &ip src as an addressable, so we could
-- pass the address at which to munge as an argument to the handlers
-- without assuming a certain encapsulation.
local dispatch_template = [[
(incoming, outgoing) => {
  ip src $external_ip => incoming()
  ip dst $internal_ip => outgoing()
}]]

local function make_dispatcher(conf)
   local external_ip = str_ip_to_uint32(conf.external_ip)
   local internal_ip = str_ip_to_uint32(conf.internal_ip)
   local function incoming(pkt, len)
      set_src_ip(pkt, len, internal_ip)
      fix_checksums(pkt, len)
   end
   local function outgoing(pkt, len)
      set_dst_ip(pkt, len, external_ip)
      fix_checksums(pkt, len)
   end
   return pf.dispatch.compile(subst(dispatch_template, conf))(
      incoming, outgoing)
end

function BasicNAT:new (conf)
   local c = {dispatch = make_dispatcher(conf)}
   return setmetatable(c, {__index=BasicNAT})
end

function BasicNAT:push ()
   local i, o = self.input.input, self.output.output
   local pkt = link.receive(i)
   self.dispatch(pkt, pkt.length)
   link.transmit(o, natted_pkt)
end
