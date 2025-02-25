import base64
from http import HTTPStatus
from tplinkrouterc6u.client.mr import TPLinkMRClient, TPLinkMRClientBase
from tplinkrouterc6u.common.exception import ClientException
from time import time, sleep
from logging import Logger
from tplinkrouterc6u.common.exception import ClientException


class TPLinkVRClientBase(TPLinkMRClientBase):

    def __init__(self, host: str, password: str, username: str = 'admin', logger: Logger = None,
                 verify_ssl: bool = True, timeout: int = 30):
        super().__init__(host, password, username, logger, verify_ssl, timeout) 
        self._url_rsa_key = 'cgi/getGDPRParm'

    def supports(self):
        return self._verify_router() and super().supports()
    
    def _verify_router(self) -> bool:
        """
        Verifies if the connected router is a supported TP-Link VR model.

        This function checks if the router is a TP-Link VR model by sending a GET request
        to the host and analyzing the response. It verifies the presence of specific 
        keywords and endpoints in the response to determine the model type.

        Returns:
            bool: True if the router is a supported TP-Link VR model and supports the RSA key endpoint, 
                otherwise False.

        Raises:
            Exception: If an error occurs during the request process, it logs the error
                    and returns False.
        """

        is_VR = False
        has_url_rsa_endpoint = False

        status_code = None
        response = None

        try:
            status_code, response = self._request(self.host, method='GET')
        except:
            if self._logger is not None:
                self._logger.error("Error while checking modem: {}".format(e))

            return False

        if status_code ==  HTTPStatus.OK:
            is_VR = "Archer VR" in response
            has_url_rsa_endpoint = self._url_rsa_key in response

        if has_url_rsa_endpoint and is_VR:
            return True
        elif is_VR:
            #check if lib.js is present. If response code is 200, it is okay. Check if self._url_rsa_key is present
            try:
                status_code, response = self._request("{}/js/lib.js".format(self.host), method='GET')
            except Exception as e:
                if self._logger is not None:
                    self._logger.error("Error while checking if lib.js is present in modem: {}".format(e))

                #if lib.js is not present, return False. Are API not compatible to this class?
                return False
            
            if status_code == HTTPStatus.OK:
                has_url_rsa_endpoint = (self._url_rsa_key in response)

            return is_VR and has_url_rsa_endpoint
        else:
            #modem is not VR
            return False
        
    
    def _get_url(self, endpoint: str, params: dict = {}, include_ts: bool = True) -> str:
        params_dict = {}
        params_arr = []
        # add timestamp param
        if include_ts:
            params_dict['_'] = str(round(time() * 1000))

        # format params into a string
        for attr, value in params.items():
            params_arr.append('{}={}'.format(attr, value))

        # format url
        return '{}/{}{}{}'.format(
            self.host,
            endpoint,
            '?' if len(params_dict) > 0 else '',
            '&'.join(params_dict)
        )
    
    def _req_login(self) -> None:
        '''
        Authenticates to the host
            - sets the session token after successful login
            - data/signature is passed as a GET parameter, NOT as a raw request data
              (unlike for regular encrypted requests to the /cgi_gdpr endpoint)

        Example session token (set as a cookie):
            {'JSESSIONID': '4d786fede0164d7613411c7b6ec61e'}
        '''
        #self.password to base64 string
        base64pwd = base64.b64encode(self.password.encode('utf-8')).decode('utf-8')
#        sign, data = self._prepare_data(self.username + '\n' + str(base64pwd), True)

        data_list = []
        data_list.append("UserName={}".format(self.username))
        data_list.append("Passwd={}".format(base64pwd))
        

        actItem = self.ActItem(self.ActItem.CGI, '/cgi/login', attrs= data_list)
        response, _ = self.req_act([actItem])

        ret_code = self._parse_ret_val(response)
        if ret_code == self.HTTP_RET_OK:
            return

        if ret_code == self.HTTP_ERR_USER_PWD_NOT_CORRECT:

            error = 'TplinkRouter - MR - Login failed, wrong password.'
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

        if ret_code == self.HTTP_ERR_USER_LOCKED:
            error = 'TplinkRouter - MR - Login failed, user is locked.'
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)
        
        if ret_code == self.HTTP_ERR_USER_BAD_REQUEST:
            error = 'TplinkRouter - MR - Login failed. Generic error code: {}'.format(ret_code)
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

        # unknown error
        error = 'TplinkRouter - MR - Login failed. Unknown error code: {}'.format(ret_code)
        if self._logger:
            self._logger.debug(error)
        raise ClientException(error)

    def _request(self, url, method='POST', data_str=None, encrypt=False):
        '''
        Prepares and sends an HTTP request to the host
            - sets up the headers, handles token auth
            - encrypts/decrypts the data, if needed

        Return value:
            (status_code, response_text) tuple
        '''
        headers = self.HEADERS

        # add referer to request headers,
        # otherwise we get 403 Forbidden
        headers['Referer'] = self.host

        # add token to request headers,
        # used for CGI auth (together with JSESSIONID cookie)
        if self._token is not None:
            headers['TokenID'] = self._token

        # encrypt request data if needed (for the /cgi_gdpr endpoint)
        if encrypt:
            #check if data_str contains /cgi/login
            is_login =  '/cgi/login' in data_str
            
            sign, data = self._prepare_data(data_str, is_login)
            data = 'sign={}\r\ndata={}\r\n'.format(sign, data)
        else:
            data = data_str

        retry = 0
        while retry < self.REQUEST_RETRIES:
            # send the request
            if method == 'POST':
                r = self.req.post(url, data=data, headers=headers, timeout=self.timeout, verify=self._verify_ssl)
            elif method == 'GET':
                r = self.req.get(url, data=data, headers=headers, timeout=self.timeout, verify=self._verify_ssl)
            else:
                raise Exception('Unsupported method ' + str(method))

            # sometimes we get 500 here, not sure why... just retry the request
            if r.status_code != 500 and '<title>500 Internal Server Error</title>' not in r.text:
                break

            sleep(0.05)
            retry += 1

        # decrypt the response, if needed
        if encrypt and (r.status_code == 200) and (r.text != ''):
            return r.status_code, self._encryption.aes_decrypt(r.text)
        else:
            return r.status_code, r.text



class TPLinkVRClient(TPLinkVRClientBase, TPLinkMRClient):
    def __init__(self, host, username, password, logger=None, verify_ssl=True, timeout=30):
        super().__init__(host, username, password, logger, verify_ssl, timeout)