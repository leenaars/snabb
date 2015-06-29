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

local function ipv4_checksum(pkt, ip_base, len)
   local checksum = 0
   for i = ip_base, ip_base + 18, 2 do
      if i ~= ip_base + 10 then -- The checksum bytes are assumed to be 0
         checksum = checksum + pkt.data[i] * 0x100 + pkt.data[i+1]
      end
   end
   return csum_carry_and_not(checksum)
end

local function tcp_checksum(pkt, ip_base, tcp_base, tcp_len)
   local checksum = 0
   -- First 64 bytes of the TCP pseudo-header: the ip addresses
   for i = ip_base + 12, ip_base + 18, 2 do
      checksum = checksum + pkt.data[i] * 0x100 + pkt.data[i+1]
   end
   -- Add the protocol field of the IPv4 header to the checksum
   local protocol = pkt.data[ip_base + 9]
   checksum = checksum + protocol
   local tcplen = pkt.data[ip_base + 2] * 0x100 + pkt.data[ip_base + 3] - 20
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

local function udp_checksum(pkt, base, len)
   -- ipv4 udp checksums are optional
   return 0
end

local function fix_tcp_checksums(pkt, ip_base, tcp_base, payload_len)
   local transport_csum = tcp_checksum(pkt, ip_base, tcp_base, payload_len)
   pkt.data[tcp_base + 16] = bit.rshift(transport_csum, 8)
   pkt.data[tcp_base + 17] = bit.band(transport_csum, 0xff)
end

local function fix_udp_checksums(pkt, udp_base, payload_len)
   local transport_csum = udp_checksum(pkt, udp_base, payload_len)
   pkt.data[udp_base + 6] = bit.rshift(transport_csum, 8)
   pkt.data[udp_base + 7] = bit.band(transport_csum, 0xff)
end

local function fix_ip_checksums(pkt, ip_base, header_size)
   local ipchecksum = ipv4_checksum(pkt, ip_base_header_size)
   pkt.data[ip_base + 10] = bit.rshift(ipchecksum, 8)
   pkt.data[ip_base + 11] = bit.band(ipchecksum, 0xff)
end

local function set_src_ip(pkt, ip_base, ip)
   local a, b, c, d = uint32_to_bytes(ip)
   pkt.data[ip_base + 12] = a
   pkt.data[ip_base + 13] = b
   pkt.data[ip_base + 14] = c
   pkt.data[ip_base + 15] = d
   return pkt
end

local function set_dst_ip(pkt, ip_base, ip)
   local a, b, c, d = uint32_to_bytes(ip)
   pkt.data[ip_base + 16] = a
   pkt.data[ip_base + 17] = b
   pkt.data[ip_base + 18] = c
   pkt.data[ip_base + 19] = d
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

-- todo: add comment syntax, "else"
local dispatch_template = [[
(incoming_tcp, incoming_udp, incoming_other,
 outgoing_tcp, outgoing_udp, outgoing_other) => {
  ip src $external_ip => {
    tcp => incoming_tcp(&ip[0], &ip_payload[0])
    udp => incoming_udp(&ip[0], &ip_payload[0])
    _ => incoming_other(&ip[0], &ip_payload[0])
  }
  ip dst $internal_ip => {
    tcp => outgoing_tcp(&ip[0], &ip_payload[0])
    udp => outgoing_udp(&ip[0], &ip_payload[0])
    _ => outgoing_other(&ip[0], &ip_payload[0])
  }
}]]

local function make_dispatcher(conf)
   local external_ip = str_ip_to_uint32(conf.external_ip)
   local internal_ip = str_ip_to_uint32(conf.internal_ip)
   local function incoming_tcp(pkt, len, ip_base, tcp_base)
      set_src_ip(pkt, len, ip_base, internal_ip)
      fix_ip_checksums(pkt, ip_base, tcp_base - ip_base)
      fix_tcp_checksums(pkt, tcp_base, len - tcp_base)
   end
   local function incoming_udp(pkt, len, ip_base, udp_base)
      set_src_ip(pkt, ip_base, internal_ip)
      fix_ip_checksums(pkt, ip_base, udp_base - ip_base)
      fix_udp_checksums(pkt, udp_base, len - udp_base)
   end
   local function incoming_other(pkt, len, ip_base, payload_base)
      set_src_ip(pkt, ip_base, internal_ip)
      fix_ip_checksums(pkt, ip_base, udp_base - ip_base)
   end
   local function outgoing_tcp(pkt, len, ip_base, tcp_base)
      set_dst_ip(pkt, ip_base, external_ip)
      fix_ip_checksums(pkt, ip_base, tcp_base - ip_base)
      fix_tcp_checksums(pkt, tcp_base, len - tcp_base)
   end
   local function outgoing_udp(pkt, len, ip_base, udp_base)
      set_dst_ip(pkt, ip_base, external_ip)
      fix_ip_checksums(pkt, ip_base, udp_base - ip_base)
      fix_udp_checksums(pkt, udp_base, len - udp_base)
   end
   local function outgoing_other(pkt, len, ip_base, payload_base)
      set_dst_ip(pkt, len, ip_base, external_ip)
      fix_ip_checksums(pkt, ip_base, udp_base - ip_base)
   end
   return pf.dispatch.compile(subst(dispatch_template, conf))(
      incoming_tcp, incoming_udp, incoming_other,
      outgoing_tcp, outgoing_udp, outgoing_other)
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
