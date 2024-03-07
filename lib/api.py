import base64
import hmac
import random
import string
import time
from hashlib import sha1, sha256
from typing import Optional

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from lib.models import AVFrame


def gen_nonce(length):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join(random.choice(alphabet) for _ in range(length))


class Api:
    def __init__(self):
        self._user_id = None
        self._token = None
        self._token_secret = None
        self._pwd = None
        self._license = None
        self._base_nonce = gen_nonce(7)

    def calc_hmac(self, params: dict[str, str]) -> str:
        data = '&'.join([f'{key}={value}' for key, value in params.items()])
        signature = hmac.new(f'{self._token}&{self._token_secret}'.encode(), data.encode(), sha1).digest()
        return base64.b64encode(signature).decode()

    def call_api(self, path: str, params: dict[str, str], signed=True):
        if not path.startswith('/'):
            path = '/' + path

        url = 'http://gw-eu.xiaoyi.com'
        url += path
        if signed:
            # params order is important for the hmac
            params['hmac'] = self.calc_hmac(params)

        resp = requests.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def login(self, account: str, password: str):
        password = hmac.new(b'KXLiUdAsO81ycDyEJAeETC$KklXdz3AC', password.encode(), sha256).digest()

        resp = self.call_api('/v4/users/login', {
            'dev_name': 'xiaomi',
            'password': base64.b64encode(password).decode(),
            'dev_os_version': 'Android 10',
            'dev_type': 'Redmi Note 7',
            'seq': '1',
            'account': account
        }, False)
        assert resp['code'] == '20000', f'{resp["code"] = }'
        self._user_id = resp['data']['userid']
        self._token = resp['data']['token']
        self._token_secret = resp['data']['token_secret']

    def vmanager_need_upgrade(self, uid: str, sname: str, version: str) -> bool:
        resp = self.call_api('/vmanager/upgrade', {
            'uid': uid,
            'protocol': 'mieu',
            'sname': sname,
            'version': version,
        }, signed=False)
        assert resp['code'] == 20000, f'{resp["code"] = }'
        return resp['needUpdate']

    def vmanager_download_upgrade(self, uid: str, sname: str, version: str) -> Optional[bytes]:
        resp = self.call_api('/vmanager/upgrade', {
            'uid': uid,
            'protocol': 'mieu',
            'sname': sname,
            'version': version,
        }, signed=False)
        assert resp['code'] == 20000, f'{resp["code"] = }'

        if resp['needUpdate'] != 'true':
            return None

        resp = requests.get(resp['downloadPath'] + resp['fileName'])
        resp.raise_for_status()

        return resp.content

    def fetch_device_password(self, device_uid: str, pin_code: str):
        resp = self.call_api('/v5/devices/password', {
            'seq': '1',
            'userid': str(self._user_id),
            'uid': device_uid,
            'pincode': pin_code,
        })
        assert resp['code'] == '20000', f'{resp["code"] = }'
        return resp['data']['password']

    def devices_list(self):
        resp = self.call_api('/v4/devices/list', {
            'seq': '1',
            'userid': str(self._user_id),
        })
        assert resp['code'] == '20000', f'{resp["code"] = }'
        return resp['data']

    def device_info(self, device_uid: str):
        resp = self.call_api('/v4/tnp/device_info', {
            'seq': '1',
            'userid': str(self._user_id),
            'uid': device_uid,
        })
        assert resp['code'] == '20000', f'{resp["code"] = }'
        self._license = resp['data']['License'][:-1]

    def init_device(self, device_uid: str, pin_code: str):
        master_pwd = self.fetch_device_password(device_uid, pin_code)
        pwd = AES.new(device_uid[:16].encode(), AES.MODE_ECB).decrypt(bytes.fromhex(master_pwd))
        self._pwd = unpad(pwd, 16)

    def gen_auth_info(self):
        assert self._pwd is not None

        nonce = self._base_nonce + gen_nonce(8)
        auth = base64.b64encode(hmac.new(self._pwd, b'user=xiaoyiuser&nonce=' + nonce.encode(), sha1).digest()).decode()
        auth = auth[:15]
        return nonce, auth

    def decrypt_iframe(self, frame: AVFrame):
        assert frame.is_iframe()
        assert len(frame.frame_data) >= 36

        aes = AES.new(self._pwd + b'0', AES.MODE_ECB)
        frame.frame_data[4:20] = aes.decrypt(frame.frame_data[4:20])
        frame.frame_data[20:36] = aes.decrypt(frame.frame_data[20:36])

    def sign_packet(self, uid: tuple[str, int, str]):
        assert self._license is not None

        nonce = f'{int(time.time() * 1000)}:'
        for _ in range(32 - len(nonce)):
            nonce += random.choice(string.ascii_lowercase + string.ascii_uppercase)

        assert len(nonce) == 32

        prefix, serial, check_code = uid
        to_sign = f'{nonce}:{prefix}-{serial}-{check_code}'
        signature = hmac.new(self._license.encode(), to_sign.encode(), sha1).digest()
        return nonce.encode(), signature.hex()[:32].upper().encode()
