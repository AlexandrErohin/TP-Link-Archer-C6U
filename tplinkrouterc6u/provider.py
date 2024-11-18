from logging import Logger

from tplinkrouterc6u import TPLinkXDRClient
from tplinkrouterc6u.common.exception import ClientException, AuthorizeError
from tplinkrouterc6u.client.c6u import TplinkRouter
from tplinkrouterc6u.client.deco import TPLinkDecoClient
from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.client.mr import TPLinkMRClient
from tplinkrouterc6u.client.ex import TPLinkEXClient
from tplinkrouterc6u.client.c6v4 import TplinkC6V4Router
from tplinkrouterc6u.client.c5400x import TplinkC5400XRouter
from tplinkrouterc6u.client.c1200 import TplinkC1200Router


class TplinkRouterProvider:
    @staticmethod
    def get_client(host: str, password: str, username: str = 'admin', logger: Logger = None,
                   verify_ssl: bool = True, timeout: int = 30) -> AbstractRouter:
        for client in [TplinkC5400XRouter, TPLinkEXClient, TPLinkMRClient, TplinkC6V4Router, TPLinkDecoClient,
                       TPLinkXDRClient, TplinkRouter]:
            router = client(host, password, username, logger, verify_ssl, timeout)
            if router.supports():
                return router

        router = TplinkC1200Router(host, password, username, logger, verify_ssl, timeout)
        try:
            router.authorize()
            return router
        except AuthorizeError as e:
            if logger:
                logger.error(e.__str__())
            raise ClientException(('Login failed! Please check if your router local password is correct or '
                                   'try to use web encrypted password instead. Check the documentation!'
                                   ))
        except Exception as e:
            if logger:
                logger.error(e.__str__())
            raise ClientException('Try to use web encrypted password instead. Check the documentation! '
                                  + e.__str__())
