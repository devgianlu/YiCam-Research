import itertools
import threading
from queue import Queue
from typing import Iterator

from lib.models import AVFrame
from lib.pppp import Client, decode_tnp_packet


class TNP:
    def __init__(self, client: Client):
        self.client = client
        self._use_count = itertools.cycle([i for i in range(256)])

        self._video_p_thread = threading.Thread(target=self._video_loop, args=(3,))
        self._video_p_thread.start()

        self._video_i_thread = threading.Thread(target=self._video_loop, args=(2,))
        self._video_i_thread.start()

        self._video_queue = Queue[AVFrame]()

    def _video_loop(self, channel):
        buffer = bytearray()

        last_pkt_index = -1
        while True:
            if len(buffer) < 8:
                while True:
                    pkt_index, data = self.client.conn.recv_drw(channel)
                    if pkt_index == last_pkt_index + 1 or last_pkt_index == -1:
                        buffer += data
                        last_pkt_index = pkt_index
                        break

            try:
                _, pkt_size, _ = decode_tnp_packet(buffer)
                buffer = buffer[8:]
            except AssertionError as e:
                raise ValueError(f'#{channel}: {str(e)}')

            pkt_body = buffer[:pkt_size]
            buffer = buffer[pkt_size:]

            while len(pkt_body) < pkt_size:
                while True:
                    pkt_index, data = self.client.conn.recv_drw(channel)
                    if pkt_index == last_pkt_index + 1:
                        buffer += data
                        last_pkt_index = pkt_index
                        break

                remaining = pkt_size - len(pkt_body)
                pkt_body += buffer[:remaining]
                buffer = buffer[remaining:]

            assert len(pkt_body) == pkt_size

            av_frame = AVFrame.parse(pkt_body)
            if self._video_queue.qsize() > 100:
                self._video_queue.get_nowait()
                self._video_queue.task_done()

            self._video_queue.put_nowait(av_frame)

    def drain_video(self) -> Iterator[AVFrame]:
        while True:
            frame = self._video_queue.get(block=True)
            self._video_queue.task_done()
            yield frame

    def start_realtime(self, resolution: int, version: int):
        data = next(self._use_count).to_bytes(1, 'big')
        data += resolution.to_bytes(1, 'big')
        data += version.to_bytes(1, 'big')
        cmd_type, _, _ = self.client.send_io_ctrl(0x2345, data)
        assert cmd_type == 0x1312

    def set_resolution(self, resolution: int):
        data = resolution.to_bytes(4, 'big') + next(self._use_count).to_bytes(4, 'big')
        cmd_type, _, _ = self.client.send_io_ctrl(0x1311, data)
        assert cmd_type == 0x1312

    def trigger_sync_info_from_server_req(self):
        cmd_type, _, _ = self.client.send_io_ctrl(0x03c0, int.to_bytes(1, 4, 'big'))
        assert cmd_type == 0x03c1

    def get_version(self):
        cmd_type, _, data = self.client.send_io_ctrl(0x1300, b'\x00\x00\x00\x00')
        assert cmd_type == 0x1301
        return data.decode()

    def get_device_info(self):
        cmd_type, _, data = self.client.send_io_ctrl(0x0330, b'\x00\x00\x00\x00')
        assert cmd_type == 0x0331
        return data
