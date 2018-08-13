#!/usr/bin/env python2

import argparse, socket, random, struct

# (attributeName, isAddress)
attrTypes = {
0x0001: ("MAPPED-ADDRESS", True),
0x0002: ("RESPONSE-ADDRESS", True),
0x0003: ("CHANGE-REQUEST", False),
0x0004: ("SOURCE-ADDRESS", True),
0x0009: ("ERROR-CODE", False),
0x0005: ("CHANGED-ADDRESS", True),
0x0020: ("XOR-MAPPED-ADDRESS", True),
0x8020: ("XOR-MAPPED-ADDRESS", True),
0x8022: ("SOFTWARE", False),
0x8023: ("ALTERNATE-SERVER", True),
0x8026: ("PADDING", False),
0x802b: ("RESPONSE-ORIGIN", True),
0x802c: ("OTHER-ADDRESS", True)}

argparser = argparse.ArgumentParser(description="Query a STUN server.", epilog="This software loosely follows the RFC 3489 and 5389 standards.")
argparser.add_argument("-t", "--tcp", action="store_true", help="use TCP instead of UDP")
argparser.add_argument("-r", "--raw", action="store_true", help="do not parse reply attributes")
argparser.add_argument("-m", "--magiccookie", action="store_true", help="signal RFC 5389 support by sending the magic cookie in the transaction ID")
argparser.add_argument("-c", "--changerequest", action="store_true", help="include the CHANGE-REQUEST attribute (empty without -A or -P)")
argparser.add_argument("-A", "--changeaddress", action="store_true", help="ask the server to reply from a different IP address (implies -c)")
argparser.add_argument("-P", "--changeport", action="store_true", help="ask the server to reply from a different port (implies -c)")
argparser.add_argument("-p", "--port", "--sourceport", type=int, default=0, help="local port to send request from (default: random)")
argparser.add_argument("-a", "--address", "--sourceaddress", default="0.0.0.0", help="local address to send request from (default: %(default)s)")
argparser.add_argument("server", default="stun.stunprotocol.org", nargs="?", help="the STUN server to be queried (default: %(default)s)")
argparser.add_argument("serverport", type=int, default=3478, nargs="?", help="the server's port to send the request to (default: %(default)s)")

opts = argparser.parse_args()
transid = struct.pack(">IIII", 0x2112A442 if opts.magiccookie else random.randrange(2**32), random.randrange(2**32), random.randrange(2**32), random.randrange(2**32))
if opts.changerequest or opts.changeaddress or opts.changeport:
 attrs = b"\0\x03\0\x04" + struct.pack(">I", opts.changeaddress << 2 | opts.changeport << 1)
else:
 attrs = b""
message = b"\0\x01" + struct.pack(">H", len(attrs)) + transid + attrs

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if opts.tcp else socket.SOCK_DGRAM)
sock.bind((opts.address, opts.port))
print("querying {}:{} from {}:{}".format(opts.server, opts.serverport, sock.getsockname()[0], sock.getsockname()[1]))
if opts.tcp:
 sock.connect((opts.server, opts.serverport))
 sock.send(message)
 reply = sock.recv(512)
 sock.close()
 print("reply")
else:
 sock.sendto(message, (opts.server, opts.serverport))
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
 attrTypeDec = attrTypes.get(attrType, ("unknown", False))
 print(" attribute type {:x} {}, value length: {}".format(attrType, attrTypeDec[0], attrValLen))
 if not opts.raw and attrTypeDec[1]: # parse address
  addrFam = struct.unpack("B", reply[i+1:i+2])[0]
  i += 2
  if addrFam == 1 and attrValLen == 8:
   addrPort = struct.unpack(">H", reply[i:i+2])[0]
   i += 2
   addr = struct.unpack("BBBB", reply[i:i+4])
   i += 4
   if attrType & 0x7fff == 0x20:
    addr = map(lambda x: x[0] ^ x[1], zip(addr, struct.unpack("BBBB", transid[0:4])))
    addrPort ^= struct.unpack(">H", transid[0:2])[0]
   print("  {}:{}".format(".".join(str(b) for b in addr), addrPort))
  elif addrFam == 2 and attrValLen == 20:
   addrPort = struct.unpack(">H", reply[i:i+2])[0]
   i += 2
   addr = struct.unpack(">HHHHHHHH", reply[i:i+16])
   i += 16
   if attrType & 0x7fff == 0x20:
    addr = map(lambda x: x[0] ^ x[1], zip(addr, struct.unpack(">HHHHHHHH", transid)))
    addrPort ^= struct.unpack(">H", transid[0:2])[0]
   print("  [{}]:{}".format(":".join("{:04x}".format(n) for n in addr), addrPort))
  else:
   i += attrValLen - 2
   print("  cannot parse address family {}".format(addrFam))
 else:
  attrVal = reply[i:i+attrValLen]
  if not opts.raw and attrType == 0x8022:
   print("  " + attrVal)
  else:
   print("  " + " ".join("{:02x}".format(ord(c)) for c in attrVal))
  i += attrValLen
