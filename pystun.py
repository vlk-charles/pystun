#!/usr/bin/env python

import sys, argparse, socket, random, struct

class Transaction(object):

 def __init__(self, opts=None):
  if opts is None: opts = globals()["opts"]
  assert type(opts) is argparse.Namespace
  self.opts = argparse.Namespace(**vars(opts)) # make local copy
  self.trans_id = struct.pack(">IIII",
   0x2112A442 if self.opts.magiccookie else random.randrange(2**32),
   random.randrange(2**32), random.randrange(2**32), random.randrange(2**32))
  self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if self.opts.tcp else socket.SOCK_DGRAM)
  self.sock.bind((self.opts.address, self.opts.port))
  if self.is_tcp():
   self.sock.connect((self.opts.server, self.opts.serverport))

 def is_tcp(self):
  return self.sock.type == socket.SOCK_STREAM

 def __str__(self):
  server, serverport = self.sock.getpeername() if self.is_tcp() else (self.opts.server, self.opts.serverport)
  return "querying {}:{} from {}:{} over {}".format(
   server, serverport, self.sock.getsockname()[0], self.sock.getsockname()[1], "TCP" if self.is_tcp() else "UDP")

 def send(self, msg):
  if self.is_tcp(): return self.sock.send(msg)
  return self.sock.sendto(msg, (self.opts.server, self.opts.serverport))

 def recvfrom(self, buffer_size=512):
  if self.is_tcp(): return (self.sock.recv(buffer_size), self.sock.getpeername())
  return self.sock.recvfrom(buffer_size)

 def close(self):
  self.sock.close()

 def make_request(self):
  if self.opts.changerequest or self.opts.changeaddress or self.opts.changeport:
   attrs = b"\0\x03\0\x04" + struct.pack(">I", self.opts.changeaddress << 2 | self.opts.changeport << 1)
  else:
   attrs = b""
  return b"\0\x01" + struct.pack(">H", len(attrs)) + self.trans_id + attrs

 def parse_addr(self, attr_val, xor=False):
  addr_fams = { # (struct_str, format_func)
   1: ("BBBB", lambda addr: "{}".format(".".join(str(b) for b in addr))),
   2: (">HHHHHHHH", lambda addr: "[{}]".format(":".join("{:04x}".format(n) for n in addr)))}
  addr_fam = struct.unpack("B", attr_val[1:2])[0]
  addr_len = struct.calcsize(addr_fams.get(addr_fam, ("", None))[0])
  if addr_fam in addr_fams and len(attr_val) == 4 + addr_len:
   addr_port = struct.unpack(">H", attr_val[2:4])[0]
   addr = struct.unpack(addr_fams[addr_fam][0], attr_val[4:4+addr_len])
   if xor:
    addr = map(lambda x: x[0] ^ x[1], zip(addr, struct.unpack(addr_fams[addr_fam][0], self.trans_id[:addr_len])))
    addr_port ^= struct.unpack(">H", self.trans_id[:2])[0]
   return addr_fams[addr_fam][1](addr) + ":{}".format(addr_port)
  return "cannot parse address family {}".format(addr_fam)

 def parse_xor_addr(self, attr_val):
  return self.parse_addr(attr_val, True)

 def parse_str(self, attr_val):
  return attr_val.decode("utf-8")

 def parse_err(self, attr_val):
  code = struct.unpack("BB", attr_val[2:4])
  return "{}{}{:02} {}".format(code[0], "." if code[0] > 9 or code[1] > 99 else "", code[1], self.parse_str(attr_val[4:]))

 def return_raw(self, attr_val):
  ord = (lambda c: c) if type(b"\0"[0]) == int else __builtins__.ord # no-op for Python 3
  return " ".join("{:02x}".format(ord(c)) for c in attr_val)

 def parse_msg(self, msg, out=sys.stdout):
  out.write(" length: {}\n".format(len(msg)))
  out.write(" length of attributes: {}\n".format(struct.unpack(">H", msg[2:4])[0]))
  if not msg[4:20] == self.trans_id:
   out.write(" Transaction ID differs!\n")

  i=20
  while i <len(msg):
   attr_type, attr_val_len = struct.unpack(">HH", msg[i:i+4])
   i += 4
   attr_type_dec = ATTR_TYPES.get(attr_type, ("unknown", Transaction.return_raw))
   out.write(" attribute type {:x} {}, value length: {}\n".format(attr_type, attr_type_dec[0], attr_val_len))
   out.write("  {}\n".format((Transaction.return_raw if self.opts.raw else attr_type_dec[1])(self, msg[i:i+attr_val_len])))
   i += attr_val_len

# (attr_name, parse_func)
ATTR_TYPES = {
0x0001: ("MAPPED-ADDRESS", Transaction.parse_addr),
0x0002: ("RESPONSE-ADDRESS", Transaction.parse_addr),
0x0003: ("CHANGE-REQUEST", Transaction.return_raw),
0x0004: ("SOURCE-ADDRESS", Transaction.parse_addr),
0x0009: ("ERROR-CODE", Transaction.parse_err),
0x0005: ("CHANGED-ADDRESS", Transaction.parse_addr),
0x0020: ("XOR-MAPPED-ADDRESS", Transaction.parse_xor_addr),
0x8020: ("XOR-MAPPED-ADDRESS", Transaction.parse_xor_addr),
0x8022: ("SOFTWARE", Transaction.parse_str),
0x8023: ("ALTERNATE-SERVER", Transaction.parse_addr),
0x8026: ("PADDING", Transaction.return_raw),
0x802b: ("RESPONSE-ORIGIN", Transaction.parse_addr),
0x802c: ("OTHER-ADDRESS", Transaction.parse_addr)}

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

if __name__ == "__main__":
 transaction = Transaction()
 request = transaction.make_request()
 print(transaction)
 transaction.parse_msg(request)
 transaction.send(request)
 reply = transaction.recvfrom()
 if transaction.is_tcp(): transaction.close()
 print("reply from {}:{}".format(reply[1][0], reply[1][1]))
 transaction.parse_msg(reply[0])
