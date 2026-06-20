from logging import Logger

from tplinkrouterc6u.client.xdr import TPLinkXDRClient
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.client.c6u import TplinkRouter, TplinkRouterV1_11
from tplinkrouterc6u.client.sg import TplinkRouterSG
from tplinkrouterc6u.client.deco import TPLinkDecoClient
from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.client.mr import TPLinkMRClient, TPLinkMRClientGCM
from tplinkrouterc6u.client.c50 import TPLinkC50Client
from tplinkrouterc6u.client.wr841 import TPLinkWR841NClient
from tplinkrouterc6u.client.mr200 import TPLinkMR200Client
from tplinkrouterc6u.client.mr6400v7 import TPLinkMR6400v7Client
from tplinkrouterc6u.client.ex import TPLinkEXClient, TPLinkEXClientGCM
from tplinkrouterc6u.client.c5400x import TplinkC5400XRouter
from tplinkrouterc6u.client.c3200 import TplinkC3200Router
from tplinkrouterc6u.client.c1200 import TplinkC1200Router
from tplinkrouterc6u.client.c80 import TplinkC80Router
from tplinkrouterc6u.client.vr import TPLinkVRClient
from tplinkrouterc6u.client.vr400v2 import TPLinkVR400v2Client
from tplinkrouterc6u.client.r import TPLinkRClient
from tplinkrouterc6u.client.wdr import TplinkWDRRouter
from tplinkrouterc6u.client.re330 import TplinkRE330Router
from tplinkrouterc6u.client.eap115 import TPLinkEAP115Client
from tplinkrouterc6u.client.cpe210 import TPLinkCPE210Client
from tplinkrouterc6u.client.sg108e import TPLinkSG108EClient
from tplinkrouterc6u.client.vr1200v import TplinkVR1200vRouter


class TplinkRouterProvider:
    @staticmethod
    def get_client(host: str, password: str, username: str = 'admin', logger: Logger = None,
                   verify_ssl: bool = True, timeout: int = 30) -> AbstractRouter:
        try:
            import requests
            import re

            clean_host = re.sub(r'^https?://', '', host).split(':')[0]
            target_username = 'user' if username == 'admin' else username
            probe_url = f"http://{clean_host}/cgi/getGDPRParm"

            # Native, clean, and fully programmatic headers
            headers = {
                "Content-Type": "text/plain;charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"http://{clean_host}/"
            }

            response = requests.post(probe_url, data=None, headers=headers, timeout=4)
            # If it responds with 200 containing keys OR generates a 406, the hardware is definitely a VR1200v
            if ("ee" in response.text and "nn" in response.text) or response.status_code == 406:
                if logger is not None:
                    logger.info('TplinkRouterProvider: Detected VR1200v hardware at %s. Loading dedicated client.', host)
                return TplinkVR1200vRouter(host, password, target_username, logger, verify_ssl, timeout)

        except Exception as e:
            if logger is not None:
                logger.debug('TplinkRouterProvider: VR1200v probe not applicable for %s: %s', host, e)

        for client_name, client in TplinkRouterProvider.get_clients().items():
            if isinstance(client, TplinkC1200Router):
                continue
            router = client(host, password, username, logger, verify_ssl, timeout)
            if router.supports():
                return router
            elif logger is not None:
                logger.debug('TplinkRouterProvider: supports() failed for %s (%s)', host, client.__name__)

        message = ('Login failed! Please check if your router local password is correct,'
                   'check if the default router username is correct or '
                   'try to use web encrypted password instead. Check the documentation!')
        router = TplinkC1200Router(host, password, username, logger, verify_ssl, timeout)
        try:
            router.authorize()
            return router
        except Exception:
            pass

        for client in [TPLinkVRClient, TPLinkXDRClient]:
            router = client(host, password, username, None, verify_ssl, timeout)
            try:
                router.authorize()
                message = ('Your router might be supported by {}. Please open the issue here '
                           'https://github.com/AlexandrErohin/TP-Link-Archer-C6U').format(router.__class__)
                break
            except Exception:
                pass

        raise ClientException(message)

    @staticmethod
    def get_clients() -> dict[str, type[AbstractRouter]]:
        return {
            TplinkC5400XRouter.__name__: TplinkC5400XRouter,
            TPLinkVRClient.__name__: TPLinkVRClient,
            TPLinkEXClientGCM.__name__: TPLinkEXClientGCM,
            TPLinkEXClient.__name__: TPLinkEXClient,
            TPLinkC50Client.__name__: TPLinkC50Client,
            TPLinkWR841NClient.__name__: TPLinkWR841NClient,
            TPLinkMRClientGCM.__name__: TPLinkMRClientGCM,
            TPLinkMRClient.__name__: TPLinkMRClient,
            TPLinkMR200Client.__name__: TPLinkMR200Client,
            TPLinkMR6400v7Client.__name__: TPLinkMR6400v7Client,
            TPLinkVR400v2Client.__name__: TPLinkVR400v2Client,
            TPLinkDecoClient.__name__: TPLinkDecoClient,
            TPLinkXDRClient.__name__: TPLinkXDRClient,
            TPLinkRClient.__name__: TPLinkRClient,
            TplinkRouterSG.__name__: TplinkRouterSG,
            TplinkRouterV1_11.__name__: TplinkRouterV1_11,
            TplinkRouter.__name__: TplinkRouter,
            TplinkC80Router.__name__: TplinkC80Router,
            TplinkWDRRouter.__name__: TplinkWDRRouter,
            TplinkRE330Router.__name__: TplinkRE330Router,
            TplinkC3200Router.__name__: TplinkC3200Router,
            TPLinkEAP115Client.__name__: TPLinkEAP115Client,
            TPLinkCPE210Client.__name__: TPLinkCPE210Client,
            TPLinkSG108EClient.__name__: TPLinkSG108EClient,
            TplinkC1200Router.__name__: TplinkC1200Router,
            TplinkVR1200vRouter.__name__: TplinkVR1200vRouter,
        }
