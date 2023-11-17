import hashlib
import re
from collections.abc import Callable
import json
from aiohttp.hdrs import REFERER
import aiohttp
from aiohttp.client import ClientSession, ClientResponse
from logging import Logger
from tplinkrouterc6u.encryption import EncryptionWrapper
from tplinkrouterc6u.enum import Wifi
from tplinkrouterc6u.dataclass import Firmware, Status, Device


class TplinkRouter:
    _session: ClientSession | None = None

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.single_request_mode = True
        self._logger = logger

        self._stok = ''
        self._sysauth = ''

        self._login = True
        self._seq = ''
        self._hash = hashlib.md5((self.username + self.password).encode()).hexdigest()

        self.nn = ''
        self.ee = ''

        self._pwdNN = ''
        self._pwdEE = ''

        self._encryption = EncryptionWrapper()

    async def test_connect(self) -> None:
        try:
            await self.authorize()
        finally:
            await self.clear()

    async def get_firmware(self) -> Firmware | None:
        return await self._request(self._get_firmware)

    async def get_status(self) -> Status | None:
        return await self._request(self._get_status)

    async def get_full_info(self) -> tuple[Firmware, Status] | None:
        async def callback():
            firmware = await self._get_firmware()
            status = await self._get_status()

            return firmware, status

        return await self._request(callback)

    async def set_wifi(self, wifi: Wifi, enable: bool) -> None:
        async def callback():
            path = f"admin/wireless?&form=guest&form={wifi.value}"
            data = f"operation=write&{wifi.value}_enable={'on' if enable else 'off'}"
            await self._send_data(path, data)

        await self._request(callback)

    async def reboot(self):
        async def callback():
            await self._send_data('admin/system?form=reboot', 'operation=write')

        await self._request(callback)

    async def authorize(self) -> bool:
        self._session = aiohttp.ClientSession()

        referer = 'http://{}/webpages/login.html?t=1596185370610'.format(self.host)

        if self._pwdNN == '':
            await self._request_pwd(referer)

        if self._seq == '':
            await self._request_seq(referer)

        response = await self._try_login(referer)

        if 'text/plain' == response.content_type:
            await self._request_pwd(referer)
            await self._request_seq(referer)
            response = await self._try_login(referer)

        try:
            jsonData = await response.json()

            encryptedResponseData = jsonData['data']
            responseData = self._encryption.aes_decrypt(encryptedResponseData)

            responseDict = json.loads(responseData)

            if not responseDict['success']:
                raise Exception(responseDict['errorcode'])

            self._stok = responseDict['data']['stok']
            regex_result = re.search(
                'sysauth=(.*);', response.headers['set-cookie'])
            self._sysauth = regex_result.group(1)
            self._login = False
            return True
        except (ValueError, KeyError, AttributeError) as e:
            if self._logger:
                self._logger.error("Couldn't fetch auth tokens! Response was: %s", response.text)

        return False

    async def logout(self) -> None:
        if self._session:
            await self._send_data('admin/system?form=logout', 'operation=write')
        await self.clear()

    async def clear(self) -> None:
        self._stok = ''
        self._sysauth = ''
        self._login = True
        if self._session:
            await self._session.close()
            self._session = None

    async def _get_firmware(self) -> Firmware:
        data = await self._get_data('admin/firmware?form=upgrade')
        firmware = Firmware(data['hardware_version'], data['model'], data['firmware_version'])

        return firmware

    async def _get_status(self) -> Status:

        def _calc_cpu_usage(data: dict) -> float:
            return (data['cpu_usage'] + data['cpu1_usage'] + data['cpu2_usage'] + data['cpu3_usage']) / 4

        data = await self._get_data('admin/status?form=all')
        status = Status
        status.devices = []
        status.macaddr = data['lan_macaddr']
        status.wan_ipv4_uptime = data.get('wan_ipv4_uptime')
        status.mem_usage = data['mem_usage']
        status.cpu_usage = _calc_cpu_usage(data)
        status.wired_total = len(data['access_devices_wired']) if data.__contains__('access_devices_wired') else 0
        status.wifi_clients_total = len(data['access_devices_wireless_host']) if (
            data.__contains__('access_devices_wireless_host')) else 0
        status.guest_clients_total = len(data['access_devices_wireless_guest']) if data.__contains__(
            'access_devices_wireless_guest') else 0
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total
        status.guest_2g_enable = data['guest_2g_enable'] == 'on'
        status.guest_5g_enable = data['guest_5g_enable'] == 'on'
        status.wifi_2g_enable = data['wireless_2g_enable'] == 'on'
        status.wifi_5g_enable = data['wireless_5g_enable'] == 'on'

        if data.__contains__('access_devices_wireless_host'):
            for item in data['access_devices_wireless_host']:
                type = Wifi.WIFI_2G if '2.4G' == item['wire_type'] else Wifi.WIFI_5G
                status.devices.append(Device(type, item['macaddr'], item['ipaddr'], item['hostname']))

        if data.__contains__('access_devices_wireless_guest'):
            for item in data['access_devices_wireless_guest']:
                type = Wifi.WIFI_GUEST_2G if '2.4G' == item['wire_type'] else Wifi.WIFI_GUEST_5G
                status.devices.append(Device(type, item['macaddr'], item['ipaddr'], item['hostname']))

        return status

    async def _request_pwd(self, referer: str) -> None:
        url = 'http://{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host)

        # If possible implement RSA encryption of password here.
        response = await self._session.post(url, params={'operation': 'read'}, headers={REFERER: referer}, timeout=4)

        jsonData = await response.json()

        if not jsonData['success']:
            raise Exception('Unkown error: ' + jsonData)

        args = jsonData['data']['password']

        self._pwdNN = args[0]
        self._pwdEE = args[1]

    async def _request_seq(self, referer: str) -> None:
        url = 'http://{}/cgi-bin/luci/;stok=/login?form=auth'.format(self.host)

        # If possible implement RSA encryption of password here.
        response = await self._session.post(url, params={'operation': 'read'}, headers={REFERER: referer}, timeout=4)

        jsonData = await response.json()

        if not jsonData['success']:
            raise Exception('Unkown error: ' + jsonData)

        self._seq = jsonData['data']['seq']
        args = jsonData['data']['key']

        self.nn = args[0]
        self.ee = args[1]

    async def _try_login(self, referer: str) -> ClientResponse:
        url = 'http://{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)

        cryptedPwd = self._encryption.rsa_encrypt(self.password, self._pwdNN, self._pwdEE)
        data = 'operation=login&password={}&confirm=true'.format(cryptedPwd)

        body = self._prepare_data(data)

        return await self._session.post(
            url, data=body,
            headers={REFERER: referer, 'Content-Type': 'application/x-www-form-urlencoded'}, timeout=4)

    def _prepare_data(self, data):
        encrypted_data = self._encryption.aes_encrypt(data)
        data_len = len(encrypted_data)

        sign = self._encryption.get_signature(int(self._seq) + data_len, self._login, self._hash, self.nn, self.ee)

        return {'sign': sign, 'data': encrypted_data}

    async def _request(self, callback: Callable):
        if not self.single_request_mode:
            return await callback()

        try:
            if await self.authorize():
                data = await callback()
                await self.logout()
                return data
        except Exception as error:
            self._seq = ''
            self._pwdNN = ''
            if self._logger:
                self._logger.error(error)
        finally:
            await self.clear()

    async def _get_data(self, path: str) -> dict | None:
        if self._session is None:
            raise Exception('Not authorised')
        url = 'http://{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)
        referer = 'http://{}/webpages/index.html'.format(self.host)

        response = await self._session.post(
            url, params={'operation': 'read'}, headers={REFERER: referer},
            cookies={'sysauth': self._sysauth}, timeout=5)

        try:
            json_response = await response.json()

            data = json_response['data']
            data = self._encryption.aes_decrypt(data)

            json_response = json.loads(data)

            if json_response['success']:
                return json_response['data']
            else:
                if json_response['errorcode'] == 'timeout':
                    if self._logger:
                        self._logger.info("Token timed out. Relogging on next scan")
                    self._stok = ''
                    self._sysauth = ''
                elif self._logger:
                    self._logger.error("An unknown error happened while fetching data")
        except ValueError:
            if self._logger:
                self._logger.error("Router didn't respond with JSON. Check if credentials are correct")

        return None

    async def _send_data(self, path: str, data: str):
        if self._session is None:
            raise Exception('Not authorised')
        url = 'http://{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)
        referer = 'http://{}/webpages/index.1596185370610.html'.format(self.host)

        body = self._prepare_data(data)
        await self._session.post(
            url, data=body, headers={REFERER: referer, 'Content-Type': 'application/x-www-form-urlencoded'},
            cookies={'sysauth': self._sysauth})
