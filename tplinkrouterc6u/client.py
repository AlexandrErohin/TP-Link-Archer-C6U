import hashlib
import re
from collections.abc import Callable
import json
import requests
from logging import Logger
from tplinkrouterc6u.encryption import EncryptionWrapper
from tplinkrouterc6u.enum import Wifi
from tplinkrouterc6u.dataclass import Firmware, Status, Device


class TplinkRouter:
    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None, verify_ssl: bool = True) -> None:
        self.host = host
        if not (self.host.startswith('http://') or self.host.startswith('https://')):
            self.host = "http://{}".format(self.host)
        self._verify_ssl = verify_ssl
        if self._verify_ssl is False:
            requests.packages.urllib3.disable_warnings()
        self.username = username
        self.password = password
        self.single_request_mode = True
        self._logger = logger

        self._stok = ''
        self._sysauth = ''

        self._logged = False
        self._seq = ''
        self._hash = hashlib.md5((self.username + self.password).encode()).hexdigest()

        self.nn = ''
        self.ee = ''

        self._pwdNN = ''
        self._pwdEE = ''

        self._encryption = EncryptionWrapper()

    def get_firmware(self) -> Firmware | None:
        return self._request(self._get_firmware)

    def get_status(self) -> Status | None:
        return self._request(self._get_status)

    def get_full_info(self) -> tuple[Firmware, Status] | None:
        def callback():
            firmware = self._get_firmware()
            status = self._get_status()

            return firmware, status

        return self._request(callback)

    def set_wifi(self, wifi: Wifi, enable: bool) -> None:
        def callback():
            path = f"admin/wireless?&form=guest&form={wifi.value}"
            data = f"operation=write&{wifi.value}_enable={'on' if enable else 'off'}"
            self._send_data(path, data)

        self._request(callback)

    def reboot(self) ->None:
        def callback():
            self._send_data('admin/system?form=reboot', 'operation=write')

        self._request(callback)

    def authorize(self) -> bool:
        referer = '{}/webpages/login.html?t=1596185370610'.format(self.host)

        if self._pwdNN == '':
            self._request_pwd(referer)

        if self._seq == '':
            self._request_seq(referer)

        response = self._try_login(referer)

        if 'text/plain' == response.headers.get('Content-Type'):
            self._request_pwd(referer)
            self._request_seq(referer)
            response = self._try_login(referer)

        try:
            jsonData = response.json()

            if 'data' not in jsonData or not jsonData['data']:
                raise Exception('No data in response: ' + response.text)

            encryptedResponseData = jsonData['data']
            responseData = self._encryption.aes_decrypt(encryptedResponseData)

            responseDict = json.loads(responseData)

            if 'success' not in responseDict or not responseDict['success']:
                raise Exception('No data in response: ' + responseData)

            self._stok = responseDict['data']['stok']
            regex_result = re.search(
                'sysauth=(.*);', response.headers['set-cookie'])
            self._sysauth = regex_result.group(1)
            self._logged = True
            return True
        except (ValueError, KeyError, AttributeError) as e:
            if self._logger:
                self._logger.error("TplinkRouter Integration Exception - Couldn't fetch auth tokens! Response was: %s", response.text)

        return False

    def logout(self) -> None:
        if self._logged:
            self._send_data('admin/system?form=logout', 'operation=write')
        self.clear()

    def clear(self) -> None:
        self._stok = ''
        self._sysauth = ''
        self._logged = False

    def _get_firmware(self) -> Firmware:
        data = self._get_data('admin/firmware?form=upgrade')
        firmware = Firmware(data.get('hardware_version', ''), data.get('model', ''), data.get('firmware_version', ''))

        return firmware

    def _get_status(self) -> Status:

        def _calc_cpu_usage(data: dict) -> float | None:
            cpu_usage = (data.get('cpu_usage', 0) + data.get('cpu1_usage', 0)
                         + data.get('cpu2_usage', 0) + data.get('cpu3_usage', 0))
            return cpu_usage / 4 if cpu_usage != 0 else None

        data = self._get_data('admin/status?form=all')
        status = Status
        status.devices = []
        status.macaddr = data['lan_macaddr']
        status.wan_ipv4_uptime = data.get('wan_ipv4_uptime')
        status.mem_usage = data.get('mem_usage')
        status.cpu_usage = _calc_cpu_usage(data)
        status.wired_total = len(data.get('access_devices_wired', []))
        status.wifi_clients_total = len(data.get('access_devices_wireless_host', []))
        status.guest_clients_total = len(data.get('access_devices_wireless_guest', []))
        status.clients_total = status.wired_total + status.wifi_clients_total + status.guest_clients_total
        status.guest_2g_enable = data.get('guest_2g_enable') == 'on'
        status.guest_5g_enable = data.get('guest_5g_enable') == 'on'
        status.iot_2g_enable = data.get('iot_2g_enable') == 'on' if data.get('iot_2g_enable') is not None else None
        status.iot_5g_enable = data.get('iot_5g_enable') == 'on' if data.get('iot_5g_enable') is not None else None
        status.wifi_2g_enable = data.get('wireless_2g_enable') == 'on'
        status.wifi_5g_enable = data.get('wireless_5g_enable') == 'on'

        for item in data.get('access_devices_wireless_host', []):
            type = Wifi.WIFI_2G if '2.4G' == item['wire_type'] else Wifi.WIFI_5G
            status.devices.append(Device(type, item['macaddr'], item['ipaddr'], item['hostname']))

        for item in data.get('access_devices_wireless_guest', []):
            type = Wifi.WIFI_GUEST_2G if '2.4G' == item['wire_type'] else Wifi.WIFI_GUEST_5G
            status.devices.append(Device(type, item['macaddr'], item['ipaddr'], item['hostname']))

        return status

    def _request_pwd(self, referer: str) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host)

        # If possible implement RSA encryption of password here.
        response = requests.post(
            url, params={'operation': 'read'},
            headers={'Referer': referer},
            timeout=4,
            verify=self._verify_ssl,
        )

        try:
            data = response.json()

            args = data['data']['password']

            self._pwdNN = args[0]
            self._pwdEE = args[1]
        except Exception as error:
            raise Exception('Unknown error for pwd - {}; Response - {}'.format(error, response.text))

    def _request_seq(self, referer: str) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=auth'.format(self.host)

        # If possible implement RSA encryption of password here.
        response = requests.post(
            url,
            params={'operation': 'read'},
            headers={'Referer': referer},
            timeout=4,
            verify=self._verify_ssl,
        )

        try:
            data = response.json()

            self._seq = data['data']['seq']
            args = data['data']['key']

            self.nn = args[0]
            self.ee = args[1]
        except Exception as error:
            raise Exception('Unknown error for seq - {}; Response - {}'.format(error, response.text))

    def _try_login(self, referer: str) -> requests.Response:
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)

        cryptedPwd = self._encryption.rsa_encrypt(self.password, self._pwdNN, self._pwdEE)
        data = 'operation=login&password={}&confirm=true'.format(cryptedPwd)

        body = self._prepare_data(data)

        return requests.post(
            url,
            data=body,
            headers={'Referer': referer, 'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=4,
            verify=self._verify_ssl,
        )

    def _prepare_data(self, data) -> dict:
        encrypted_data = self._encryption.aes_encrypt(data)
        data_len = len(encrypted_data)

        sign = self._encryption.get_signature(int(self._seq) + data_len, self._logged == False, self._hash, self.nn, self.ee)

        return {'sign': sign, 'data': encrypted_data}

    def _request(self, callback: Callable):
        if not self.single_request_mode:
            return callback()

        try:
            if self.authorize():
                data = callback()
                self.logout()
                return data
        except Exception as error:
            self._seq = ''
            self._pwdNN = ''
            if self._logger:
                self._logger.error('TplinkRouter Integration Exception - {}'.format(error))
        finally:
            self.clear()

    def _get_data(self, path: str) -> dict | None:
        if self._logged is False:
            raise Exception('Not authorised')
        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)
        referer = '{}/webpages/index.html'.format(self.host)

        response = requests.post(
            url,
            params={'operation': 'read'},
            headers={'Referer': referer},
            cookies={'sysauth': self._sysauth},
            timeout=5,
            verify=self._verify_ssl,
        )

        data = response.text
        try:
            json_response = response.json()
            if 'data' not in json_response:
                raise Exception("Router didn't respond with JSON - " + data)
            data = self._encryption.aes_decrypt(json_response['data'])

            json_response = json.loads(data)

            if 'success' in json_response and json_response['success']:
                return json_response['data']
            else:
                if 'errorcode' in json_response and json_response['errorcode'] == 'timeout':
                    if self._logger:
                        self._logger.info("TplinkRouter Integration Exception - Token timed out. Relogging on next scan")
                    self._stok = ''
                    self._sysauth = ''
                elif self._logger:
                    self._logger.error("TplinkRouter Integration Exception - An unknown error happened while fetching data %s", data)
        except ValueError:
            if self._logger:
                self._logger.error("TplinkRouter Integration Exception - Router didn't respond with JSON. Check if credentials are correct")

        raise Exception('An unknown response - ' + data)

    def _send_data(self, path: str, data: str) -> None:
        if self._logged is False:
            raise Exception('Not authorised')
        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)
        referer = '{}/webpages/index.1596185370610.html'.format(self.host)

        body = self._prepare_data(data)
        requests.post(
            url,
            data=body,
            headers={'Referer': referer, 'Content-Type': 'application/x-www-form-urlencoded'},
            cookies={'sysauth': self._sysauth},
            timeout=5,
            verify=self._verify_ssl,
        )
