import itertools
import threading
from queue import Queue
from typing import Literal

from pwnlib.tubes.remote import remote

from lib.api import Api


def encode_tnp_packet(io_type: int, data: bytes) -> bytes:
    body = TNP_VERSION.to_bytes(1, 'big') + io_type.to_bytes(1, 'big')
    body += b'\x00\x00'
    body += len(data).to_bytes(4, 'big')
    body += data
    return body


def decode_tnp_packet(body: bytes):
    assert body[0] == TNP_VERSION, f'version = {body[0]}'
    io_type = body[1]
    size = int.from_bytes(body[4:8], 'big')
    return io_type, size, body[8:]


def decode_net_address(data: bytes):
    family = int.from_bytes(data[0:2], 'big')
    port = int.from_bytes(data[2:4], 'big')
    ip = data[4:8][::-1]
    return family, port, '.'.join([str(int(x)) for x in ip])


def encode_device_uid(uid: tuple[str, int, str]) -> bytes:
    prefix, serial, check_code = uid
    assert len(prefix) < 8
    assert len(check_code) < 8
    return prefix.encode().ljust(8, b'\x00') \
        + serial.to_bytes(4, 'big') \
        + check_code.encode().ljust(8, b'\x00')


def encode_net_addr(family: int, port: int, ip: str, byteorder: Literal['big', 'little']):
    return family.to_bytes(2, byteorder) \
        + port.to_bytes(2, byteorder) \
        + ip2bytes(ip, byteorder) \
        + b'\x00' * 8


def ip2bytes(ip: str, byteorder: Literal['little', 'big']) -> bytes:
    bb = bytes(map(lambda x: int(x), ip.split('.')))
    if byteorder == 'little':
        bb = bb[::-1]
    return bb


TNP_VERSION = 0x02


class Conn:
    def __init__(self, server: tuple[str, int], typ: Literal['tcp', 'udp']):
        address, port = server

        self.conn = remote(address, port, typ=typ)
        self._alive = False
        self._alive_cond = threading.Condition()

        self._pkt_index = itertools.cycle([i for i in range(0xffff)])

        self.recv_queue = Queue[tuple[int, bytes]]()
        self.recv_drw_queue = [Queue[tuple[int, bytes]]() for _ in range(8)]
        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=False)
        self.recv_thread.start()

        self.send_queue = Queue[tuple[int, bytes]]()
        self.send_loop = threading.Thread(target=self._send_loop, daemon=False)
        self.send_loop.start()

    def wait_alive(self):
        with self._alive_cond:
            if self._alive:
                return

            self._alive_cond.wait()

    def _recv_loop(self):
        while True:
            header = self.conn.recvn(4)
            assert header[0] == 0xf1, f'invalid header: {header.hex()}'
            pkt_type = header[1]
            packet_size = int.from_bytes(header[2:4], 'big')
            body = self.conn.recvn(packet_size)
            assert len(body) == packet_size

            # print('recv', hex(pkt_type), body)

            if pkt_type == 0xe0:
                self.send(0xe1, b'')

                with self._alive_cond:
                    self._alive = True
                    self._alive_cond.notify_all()
            elif pkt_type == 0xd0:
                assert body[0] == 0xd1

                chan_num = body[1]
                pkt_index = int.from_bytes(body[2:4], 'big')

                self.send_drw_ack(chan_num, [pkt_index])

                self.recv_drw_queue[chan_num].put_nowait((pkt_index, body))
            elif pkt_type == 0xd1:
                # ignore ack
                continue
            else:
                self.recv_queue.put_nowait((pkt_type, body))

    def _send_loop(self):
        while True:
            pkt_type, body = self.send_queue.get(block=True)
            self.conn.send(b'\xf1' + pkt_type.to_bytes(1, 'big') + len(body).to_bytes(2, 'big') + body)
            self.send_queue.task_done()

    def send(self, packet_type: int, body: bytes):
        self.send_queue.put_nowait((packet_type, body))

    def recv(self) -> tuple[int, bytes]:
        resp = self.recv_queue.get(block=True)
        self.recv_queue.task_done()
        return resp

    def send_drw(self, channel: int, data: bytes):
        pkt_index = next(self._pkt_index)

        body = b'\xd1' + \
               channel.to_bytes(1, 'big') + \
               pkt_index.to_bytes(2, 'big') + \
               data

        self.send(0xd0, body)

        while True:
            recv_pkt_index, body = self.recv_drw(channel)
            if recv_pkt_index == pkt_index:
                return body

    def recv_drw(self, channel: int) -> tuple[int, bytes]:
        chan_queue = self.recv_drw_queue[channel]
        pkt_index, body = chan_queue.get(block=True)
        chan_queue.task_done()

        assert body[0] == 0xd1
        assert body[1] == channel
        assert int.from_bytes(body[2:4], 'big') == pkt_index
        return pkt_index, body[4:]

    def send_drw_ack(self, channel: int, packets: list[int]):
        data = channel.to_bytes(1, 'big') + len(packets).to_bytes(2, 'big')
        for p in packets:
            data += p.to_bytes(2, 'big')

        self.send(0xd1, b'\xd1' + data)


class Client:
    def __init__(self, api: Api, server: tuple[str, int], typ: Literal['tcp', 'udp']):
        self.conn = Conn(server, typ)
        self.api = api
        self._cmd_num = itertools.cycle([i for i in range(0xfff0)])

    def send_p2p_req(self, uid: tuple[str, int, str], family: int, port: int, ip: str):
        body = encode_device_uid(uid) + encode_net_addr(family, port, ip, 'little')
        assert len(body) == 36, f'{len(body) = }'

        self.conn.send(0x20, body)
        typ, body = self.conn.recv()
        assert body[0] == 0x00

    def dev_online_req(self, uid: tuple[str, int, str]):
        body = encode_device_uid(uid)
        assert len(body) == 20, f'{len(body) = }'

        self.conn.send(0x18, body)
        typ, body = self.conn.recv()

        last_login_time = int.from_bytes(body[0:4], 'big')
        return body[4] == 1, last_login_time

    def send_rly_tcp_start(self, uid: tuple[str, int, str]):
        nonce, sig = self.api.sign_packet(uid)

        body = encode_device_uid(uid) + nonce + sig
        assert len(body) == 0x54

        self.conn.send(0x88, body)
        typ, body = self.conn.recv()
        assert typ == 0x88
        return body[:16].decode()

    def send_rly_tcp_pkt(self, ticket: str):
        assert len(ticket) == 16

        self.conn.send(0x8b, ticket.encode() + b'\x00' * 4)
        typ, body = self.conn.recv()
        assert typ == 0x8b
        assert body == b'\x00\x00\x00\x00'

    def send_rly_tcp_req(self, uid: tuple[str, int, str], ticket: str, server: tuple[str, int], family: int):
        assert len(ticket) == 16

        ip, port = server

        body = encode_device_uid(uid)
        body += encode_net_addr(family, port, ip, 'big')
        body += ticket.encode()

        self.conn.send(0x89, body)
        typ, body = self.conn.recv()
        assert typ == 0x89
        assert body == b'\x00\x00\x00\x00'

    def send_alive(self):
        self.conn.send(0xe0, b'')
        typ, _ = self.conn.recv()
        assert typ == 0xe1

    def wait_alive(self):
        self.conn.wait_alive()

    def send_hello(self):
        self.conn.send(0x00, b'')
        typ, body = self.conn.recv()
        assert typ == 0x01
        return decode_net_address(body)

    def send_tnp(self, channel: int, io_type: int, data: bytes):
        body = encode_tnp_packet(io_type, data)
        body = self.conn.send_drw(channel, body)
        recv_io_type, size, body = decode_tnp_packet(body)
        assert recv_io_type == io_type
        assert len(body) == size
        return body

    def send_io_ctrl(self, cmd_type: int, data: bytes):
        auth_info = ','.join(self.api.gen_auth_info())
        assert len(auth_info) < 32

        cmd_num = next(self._cmd_num)

        body = cmd_type.to_bytes(2, 'big')
        body += cmd_num.to_bytes(2, 'big')
        body += b'\x00\x00'  # header size
        body += len(data).to_bytes(2, 'big')
        body += auth_info.encode().ljust(32, b'\x00')
        body += data

        body = self.send_tnp(0, 3, body)

        recv_cmd_type = int.from_bytes(body[0:2], 'big')
        recv_cmd_num = int.from_bytes(body[2:4], 'big')
        assert recv_cmd_num == 65535 or cmd_num == recv_cmd_num
        assert body[4:6] == b'\x00\x00'  # header size
        data_size = int.from_bytes(body[6:8], 'big')
        auth_result = int.from_bytes(body[8:12], 'big')
        assert body[12:40] == b'\x00' * 28
        data = body[40:]
        assert len(data) == data_size

        # we should be ok with this
        assert auth_result == 0

        return recv_cmd_type, recv_cmd_num, data
