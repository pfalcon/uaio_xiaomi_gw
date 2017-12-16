import ujson
import ubinascii
import ucryptolib
import usocket
import socket
import uasyncio
from uasyncio import udp

from uaio_xiaomi_gw_cfg import *


MULTICAST_ADDRESS = "224.0.0.50"
CMD_PORT = 9898
WHOIS_PORT = 4321

GW_IV = b"\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58\x56\x2e"

MODE_CBC = 2


class XiaomiGw:

    def __init__(self):
        self.s = None
        self.gws = {}
        self.default_sid = None
        self.tokens = {}
        self.state = {}

    async def init(self):
        self.s = udp.socket()

        addr = usocket.getaddrinfo("0.0.0.0", CMD_PORT)[0][-1]
        self.s.bind(addr)

        self.cmd_addr = usocket.getaddrinfo(MULTICAST_ADDRESS, CMD_PORT)[0][-1]
        self.whois_addr = usocket.getaddrinfo(MULTICAST_ADDRESS, WHOIS_PORT)[0][-1]

        # In case inet_pton() not implemented
        #opt = bytes([224, 0, 0, 50]) + bytes([0, 0, 0, 0])
        opt = usocket.inet_pton(usocket.AF_INET, MULTICAST_ADDRESS) + usocket.inet_pton(usocket.AF_INET, "0.0.0.0")
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, opt)

    def send_msg(self, msg, whois_port=False):
        msg = ujson.dumps(msg)
        print("send_msg:", msg)
        await udp.sendto(self.s, msg, self.whois_addr if whois_port else self.cmd_addr)
#        return await self.recv_msg()

    def recv_msg(self):
        reply, addr = await udp.recvfrom(self.s, 1500)
        print("recv_msg:", reply, addr)
        return ujson.loads(reply.decode())

    def send_cmd(self, cmd, whois_port=False):
        await self.send_msg({"cmd": cmd}, whois_port)

    def process_resp(self, resp):
        cmd = resp["cmd"]
        if cmd == "heartbeat":
            sid = resp["sid"]
            if sid not in self.gws:
                self.gws[sid] = resp
            print("Updating token from heartbeat")
            self.tokens[sid] = resp["token"]
        elif cmd == "iam":
            assert int(resp["port"]) == CMD_PORT
            sid = resp["sid"]
            self.gws[sid] = resp
            if sid not in self.tokens:
                self.tokens[sid] = None
            if self.default_sid is None:
                self.default_sid = sid
        elif cmd == "get_id_list_ack":
            sid = resp["sid"]
            self.tokens[sid] = resp["token"]
            self.gws[sid]["id_list"] = resp["data"]
        elif cmd in ("report", "read_ack", "write_ack"):
            sid = resp["sid"]
            data = ujson.loads(resp["data"])
            print("* Updating %s state to: %r" % (sid, data))
            self.state[sid] = data


    async def wait_resp(self, expected=None):
        while 1:
            resp = await self.recv_msg()
            self.process_resp(resp)
            if expected is None:
                if resp["cmd"].endswith("_ack"):
                    return resp
            else:
                if resp["cmd"] == expected:
                    return resp

    async def discover(self):
        await self.send_cmd("whois", whois_port=True)
        resp = await self.wait_resp("iam")

    async def get_id_list(self):
        # Ignores sid if passed
        await self.send_cmd("get_id_list")
        resp = await self.wait_resp()

    async def read(self, sid=None):
        if not sid:
            sid = self.default_sid
        await self.send_msg({"cmd": "read", "sid": sid})
        return await self.wait_resp("read_ack")

    async def write(self, sid, data):
        cipher = ucryptolib.aes(GW_PASSWD, MODE_CBC, GW_IV)
        key = ubinascii.hexlify(cipher.encrypt(self.tokens[sid])).decode()
        data["key"] = key
        cmd = {"cmd": "write", "model": "gateway", "sid": sid, "data": data}
        await self.send_msg(cmd)
        return await self.wait_resp("write_ack")


def run(lumi):
    await lumi.init()
#    print(lumi.gws)
#    print(lumi.tokens)
#    resp = await lumi.recv_msg()
#    lumi.process_resp(resp)
    print(lumi.gws)
    print(lumi.tokens)
    await lumi.discover()
    print(lumi.gws)
    print(lumi.tokens)
    await lumi.get_id_list()
    await lumi.read()

    import utime
#    await lumi.write(lumi.default_sid, {"rgb": 0x00000000 | 0x000001}) # | (utime.ticks_us() & 0xffffff)})
    await lumi.write(lumi.default_sid, {"rgb": 0x07000000 | (utime.ticks_us() & 0xffffff)})

    while 1:
        await lumi.wait_resp()


loop = uasyncio.get_event_loop()
#task = asyncio.async(print_http_headers(url))
#loop.run_until_complete(task)

lumi = XiaomiGw()
loop.run_until_complete(run(lumi))
loop.close()
