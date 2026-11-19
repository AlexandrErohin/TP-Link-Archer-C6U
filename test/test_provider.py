from unittest import TestCase, main
from unittest.mock import patch

from tplinkrouterc6u.client.c1200 import TplinkC1200Router
from tplinkrouterc6u.client.vr import TPLinkVRClient
from tplinkrouterc6u.client.xdr import TPLinkXDRClient
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.provider import TplinkRouterProvider

ONLY_C1200 = {TplinkC1200Router.__name__: TplinkC1200Router}


@patch.object(TplinkRouterProvider, 'get_clients', return_value=ONLY_C1200)
class TestProviderGetClient(TestCase):
    """C1200 supports() only reads the RSA key, so get_client() must pick C1200 by a real login."""

    def test_c1200_is_not_chosen_by_supports(self, _get_clients) -> None:
        with patch.object(TplinkC1200Router, 'supports', return_value=True) as supports, \
                patch.object(TplinkC1200Router, 'authorize', side_effect=ClientException('login failed')), \
                patch.object(TPLinkVRClient, 'authorize', side_effect=ClientException('login failed')), \
                patch.object(TPLinkXDRClient, 'authorize', side_effect=ClientException('login failed')):
            with self.assertRaises(ClientException):
                TplinkRouterProvider.get_client('http://192.168.0.1', 'secret')

        supports.assert_not_called()

    def test_c1200_is_chosen_after_successful_login(self, _get_clients) -> None:
        with patch.object(TplinkC1200Router, 'supports', return_value=True) as supports, \
                patch.object(TplinkC1200Router, 'authorize') as authorize:
            router = TplinkRouterProvider.get_client('http://192.168.0.1', 'secret')

        self.assertIsInstance(router, TplinkC1200Router)
        authorize.assert_called_once()
        supports.assert_not_called()


if __name__ == '__main__':
    main()
