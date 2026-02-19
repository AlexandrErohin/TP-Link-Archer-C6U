from hashlib import md5
from json import dumps
from tplinkrouterc6u.client.c6u import TplinkRouter
from tplinkrouterc6u.common.package_enum import Connection
from urllib.parse import parse_qsl


class TplinkBE805Client(TplinkRouter):

    def __init__(self, host: str, password: str, username: str = 'admin', logger = None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        # BE805 seems to require/prefer JSON content type for authenticated requests
        self._headers_request['Content-Type'] = 'application/json'

        # Origin/Referer usually required by modern routers
        self._headers_request['Origin'] = f'https://{host}'
        self._headers_request['Referer'] = f'https://{host}/webpages/index.html'

    def _prepare_data(self, data: str) -> dict:
        encrypted_data = self._encryption.aes_encrypt(data)
        data_len = len(encrypted_data)
        
        # BE805 requires the full signature (Key + IV + Hash + Seq) for ALL requests,
        # not just login. This matches the behavior of 'is_login=True' in the base implementation.
        
        # Calculate hash (Standard MD5 of user+pass)
        hash_val = md5((self.username + self.password).encode()).hexdigest()
        
        # Force is_login=True to include Key/IV in the signature
        sign = self._encryption.get_signature(int(self._seq) + data_len, 
                                              True, 
                                              hash_val, self.nn, self.ee)

        return {'sign': sign, 'data': encrypted_data}



    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        values = {
            Connection.HOST_2G: 'wireless_2g',
            Connection.HOST_5G: 'wireless_5g',
            Connection.HOST_6G: 'wireless_6g',
            Connection.GUEST_2G: 'guest_2g',
            Connection.GUEST_5G: 'guest_5g',
            Connection.GUEST_6G: 'guest_6g',
            Connection.IOT_2G: 'iot_2g',
            Connection.IOT_5G: 'iot_5g',
            Connection.IOT_6G: 'iot_6g',
        }
        value = values.get(wifi)
        data = f"operation=write&enable={'on' if enable else 'off'}"
        path = f"admin/wireless?form={value}&{data}"
        self.request(path, data, ignore_response=True)

    def request(self, path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
        # BE805 expects the payload to be a JSON object, even though the base class
        # typically sends form-urlencoded style strings (e.g. 'operation=read').
        # We intercept the request, parse the string to a dict, and convert to JSON.
        
        # Also, BE805 requires the 'operation' parameter to be in the URL query string
        # for many endpoints (e.g. firmware, dhcp, vpn).
        
        if isinstance(data, str) and '=' in data:
            try:
                # content is like "operation=read&form=..."
                # Parse to dict
                parsed = dict(parse_qsl(data))
                
                # logic to append operation to path if missing
                op_val = parsed.get('operation')
                if op_val and 'operation=' not in path:
                    separator = '&' if '?' in path else '?'
                    path = f"{path}{separator}operation={op_val}"
                
                # Convert to JSON string
                data = dumps(parsed)
            except Exception:
                # If parsing fails, fall back to sending original data
                pass
        
        return super().request(path, data, ignore_response, ignore_errors)
