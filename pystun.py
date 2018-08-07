#!/usr/bin/env python2

import argparse, socket, random, struct

attrTypeEnum = {1: "MAPPED-ADDRESS", 2: "RESPONSE-ADDRESS", 3: "CHANGE-REQUEST", 4: "SOURCE-ADDRESS", 5: "CHANGED-ADDRESS", 32: "XOR-MAPPED-ADDRESS", 34: "SOFTWARE", 35: "ALTERNATE-SERVER"}

argparser = argparse.ArgumentParser(description="Query a STUN server.", epilog="This software loosely follows the RFC 3489 and 5389 standards.")
argparser.add_argument("-t", "--tcp", action="store_true", help="use TCP instead of UDP")
argparser.add_argument("-r", "--raw", action="store_true", help="do not parse reply attributes")
argparser.add_argument("-p", "--port", "--sourceport", type=int, default=0, help="local port to send request from (default: random)")
argparser.add_argument("-a", "--address", "--sourceaddress", default="0.0.0.0", help="local address to send request from (default: %(default)s)")
argparser.add_argument("server", default="stun.stunprotocol.org", nargs="?", help="the STUN server to be queried (default: %(default)s)")
argparser.add_argument("serverport", type=int, default=3478, nargs="?", help="the server's port to send the request to (default: %(default)s)")

opts = argparser.parse_args()
transid = struct.pack("IIII", random.randrange(2**32), random.randrange(2**32), random.randrange(2**32), random.randrange(2**32))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if opts.tcp else socket.SOCK_DGRAM)
sock.bind((opts.address, opts.port))
print("querying {}:{} from {}:{}".format(opts.server, opts.serverport, sock.getsockname()[0], sock.getsockname()[1]))
if opts.tcp:
 sock.connect((opts.server, opts.serverport))
 sock.send("\0\x01\0\0" + transid)
 reply = sock.recv(512)
 sock.close()
 print("reply")
else:
 sock.sendto("\0\x01\0\0" + transid, (opts.server, opts.serverport))
 reply = sock.recvfrom(512)
 print("reply from {}:{}".format(reply[1][0], reply[1][1]))
 reply = reply[0]

print(" length: {}".format(len(reply)))
print(" length of attributes: {}".format(struct.unpack(">H", reply[2:4])[0]))
if not reply[4:20] == transid:
 print(" Transaction ID differs!")

i=20
while i <len(reply):
 attrType, attrValLen = struct.unpack(">HH", reply[i:i+4])
 i += 4
 attrOpt = bool(attrType >> 15)
 attrType %= 0x8000
 print(" attribute type {} {}{}, value length: {}".format(attrType, attrTypeEnum.get(attrType, "unknown"), " (comprehension-optional)" if attrOpt else "", attrValLen))
 if not opts.raw and attrType in [1,2,4,5,32,35]: # parse address
  addrFam = struct.unpack("B", reply[i+1:i+2])[0]
  i += 2
  if addrFam == 1 and attrValLen == 8:
   addrPort = struct.unpack(">H", reply[i:i+2])[0]
   i += 2
   addr = struct.unpack("BBBB", reply[i:i+4])
   i += 4
   if attrType == 32:
    addr = map(lambda x: x[0] ^ x[1], zip(addr, struct.unpack("BBBB", transid[0:4])))
    addrPort ^= struct.unpack(">H", transid[0:2])[0]
   print("  {}:{}".format(".".join(str(b) for b in addr), addrPort))
  elif addrFam == 2 and attrValLen == 20:
   addrPort = struct.unpack(">H", reply[i:i+2])[0]
   i += 2
   addr = struct.unpack(">HHHHHHHH", reply[i:i+16])
   i += 16
   if attrType == 32:
    addr = map(lambda x: x[0] ^ x[1], zip(addr, struct.unpack(">HHHHHHHH", transid)))
    addrPort ^= struct.unpack(">H", transid[0:2])[0]
   print("  [{}]:{}".format(":".join("{:04x}".format(n) for n in addr), addrPort))
  else:
   i += attrValLen - 2
   print("  cannot parse address family {}".format(addrFam))
 else:
  attrVal = reply[i:i+attrValLen]
  if not opts.raw and attrType == 34:
   print("  " + attrVal)
  else:
   print("  " + " ".join("{:02x}".format(ord(c)) for c in attrVal))
  i += attrValLen
