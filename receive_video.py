import subprocess
import sys

from pwn import log

from lib.api import Api
from lib.pppp import Client
from lib.tnp import TNP


def parse_device_uid(uid: str) -> tuple[str, int, str]:
    parts = uid.split('-')
    assert len(parts) == 3
    return parts[0], int(parts[1]), parts[2]


def format_device_uid(uid: tuple[str, int, str]) -> str:
    return f'{uid[0]}-{uid[1]}-{uid[2]}'


UDP_SERVER = '47.254.89.110', 32100
TCP_RELAY = '45.43.63.118', 443


def main():
    api = Api()

    # authenticate and get device
    api.login(sys.argv[1], sys.argv[2])
    devices = api.devices_list()
    assert len(devices) == 1
    device_uid = parse_device_uid(devices[0]['uid'])
    log.info(f'found device: {format_device_uid(device_uid)} ({devices[0]["nickname"]})')

    # initialize device
    api.device_info(format_device_uid(device_uid))
    api.init_device(format_device_uid(device_uid), '')
    log.info('completed authentication')

    # open server connections
    udp = Client(api, UDP_SERVER, 'udp')
    tcp = Client(api, TCP_RELAY, 'tcp')

    # send hello to UDP server
    hello_addr = udp.send_hello()
    log.info(f'hello, you are {hello_addr[2]}:{hello_addr[1]}')

    # ask UDP server if device is online
    online, last_online = udp.dev_online_req(device_uid)
    if not online:
        log.error(f'device not online, last: {last_online}')
        return

    log.success('device online')

    # device is online, we want a relayed connection so ask for a ticket
    ticket = tcp.send_rly_tcp_start(device_uid)
    udp.send_rly_tcp_req(device_uid, ticket, TCP_RELAY, 2)
    tcp.send_rly_tcp_pkt(ticket)
    log.success('tcp relay open')

    # wait relay to device is ready
    tcp.wait_alive()

    tnp = TNP(tcp)
    log.info('ready to send messages')

    log.info(f'firmware version is {tnp.get_version()}')

    # request stream
    tnp.trigger_sync_info_from_server_req()
    tnp.set_resolution(2)
    tnp.start_realtime(2, 1)
    tnp.trigger_sync_info_from_server_req()
    tnp.set_resolution(0)

    log.info('stream started')

    p = subprocess.Popen(['ffplay', 'pipe:'], stdin=subprocess.PIPE)

    i = 0
    for frame in tnp.drain_video():
        if frame.is_iframe():
            api.decrypt_iframe(frame)
            log.debug('decrypted', i)
            i += 1

        # start writing only after we got an I-frame
        if i > 0:
            with open(f'frames/frame_{frame.frame_num}_{"i" if frame.is_iframe() else "p"}.bin', 'wb') as f:
                f.write(frame.frame_data)

            try:
                p.stdin.write(frame.frame_data)
            except BrokenPipeError:
                break

    p.wait()
    log.info('done')


main()
