from unittest import TestCase, main
from unittest.mock import MagicMock, patch

from tplinkrouterc6u.client.c80 import TplinkC80Router
from tplinkrouterc6u.client.mr515 import TplinkMR515Router


class TestMR515LTEStatus(TestCase):
    def setUp(self):
        self.router = TplinkMR515Router('http://192.0.2.1', 'password')

    def test_c80_does_not_expose_get_lte_status(self):
        self.assertFalse(hasattr(TplinkC80Router, 'get_lte_status'))
        self.assertTrue(hasattr(TplinkMR515Router, 'get_lte_status'))

    def test_supports_true_when_lte_block_id_echoed(self):
        # Pre-auth responses typically only echo the block id, not field payloads.
        response = MagicMock()
        response.status_code = 200
        response.text = '00000\r\nid 139|1,0,0\r\n'
        with patch.object(self.router, 'request', return_value=response) as request:
            self.assertTrue(self.router.supports())
        request.assert_called_once_with(2, 1, data='139|1,0,0')

    def test_supports_false_for_generic_c80_probe_body(self):
        response = MagicMock()
        response.status_code = 200
        response.text = '00000\r\nid 0|1,0,0\r\nmodelName Archer C80\r\n'
        with patch.object(self.router, 'request', return_value=response):
            self.assertFalse(self.router.supports())

    def test_supports_false_on_request_error(self):
        with patch.object(self.router, 'request', side_effect=RuntimeError('offline')):
            self.assertFalse(self.router.supports())

    def test_get_lte_status_parses_verified_traffic_and_limit_fields(self):
        blocks = {
            '139|1,0,0': [
                'totalStatistics 634031807641.0000',
                'limitation 644245094400',
                'curTxSpeed 1379',
                'curRxSpeed 1481',
                'enableDataLimit 0',
                'enablePaymentDay 1',
                'warningPercent 1',
                'paymentDay 29',
                'adjustStatistics 0',
            ],
        }

        with patch.object(self.router, '_return_data_block', return_value=blocks):
            status = self.router.get_lte_status()

        self.assertEqual(status.total_statistics, 634031807641)
        self.assertEqual(status.cur_rx_speed, 1481)
        self.assertEqual(status.cur_tx_speed, 1379)
        self.assertEqual(status.data_limit, 644245094400)
        self.assertIs(status.enable_data_limit, False)
        self.assertEqual(status.warning_percent, 1)
        self.assertIs(status.enable_payment_day, True)
        self.assertEqual(status.payment_day, 29)
        self.assertEqual(status.adjust_statistics, 0)

    def test_get_lte_status_parses_link_cell_mobile_and_profile(self):
        blocks = {
            '139|1,0,0': ['totalStatistics 10.0000', 'curRxSpeed 1', 'curTxSpeed 2'],
            '140|1,0,0': [
                'networkType 3',
                'simStatus 5',
                'signalStrength 3',
            ],
            '143|1,0,0': ['dataSwitchStatus 1'],
            '144|1,0,0': ['ispName ExampleISP'],
            '151|1,0,0': [
                'RSRP 1 -95',
                'RSRQ 1 -12',
                'SNR 1 85',
            ],
            '153|1,0,0': ['status 2'],
        }

        with patch.object(self.router, '_return_data_block', return_value=blocks) as ret:
            status = self.router.get_lte_status()
            requested = ret.call_args.args[0]

        self.assertNotIn('141|1,0,0', requested)
        self.assertEqual(status.enable, 1)
        self.assertEqual(status.connect_status, 1)
        self.assertEqual(status.network_type, 3)
        self.assertEqual(status.sim_status, 5)
        self.assertEqual(status.sig_level, 3)
        self.assertEqual(status.rsrp, -95)
        self.assertEqual(status.rsrq, -12)
        self.assertEqual(status.snr, 85)
        self.assertEqual(status.isp_name, 'ExampleISP')

    def test_get_lte_status_maps_non_connected_mobile_status_to_zero(self):
        blocks = {
            '153|1,0,0': ['status 1'],
        }
        with patch.object(self.router, '_return_data_block', return_value=blocks):
            status = self.router.get_lte_status()
        self.assertEqual(status.connect_status, 0)

    def test_get_lte_status_handles_prefixed_cell_fields(self):
        blocks = {
            '151|1,0,0': [
                'servingCellList 1 RSRP 1 -101',
                'servingCellList 1 RSRQ 1 -11',
                'servingCellList 1 SNR 1 42',
            ],
        }
        with patch.object(self.router, '_return_data_block', return_value=blocks):
            status = self.router.get_lte_status()
        self.assertEqual(status.rsrp, -101)
        self.assertEqual(status.rsrq, -11)
        self.assertEqual(status.snr, 42)

    def test_get_lte_status_empty_blocks_yield_nones(self):
        with patch.object(self.router, '_return_data_block', return_value={}):
            status = self.router.get_lte_status()
        self.assertIsNone(status.enable)
        self.assertIsNone(status.connect_status)
        self.assertIsNone(status.total_statistics)
        self.assertIsNone(status.rsrp)
        self.assertIsNone(status.isp_name)

    def test_lte_boolean_parser_handles_missing_and_invalid_values(self):
        self.assertIsNone(self.router._lte_bool(None))
        self.assertIsNone(self.router._lte_bool('2'))
        self.assertIs(self.router._lte_bool('0'), False)
        self.assertIs(self.router._lte_bool('1'), True)


if __name__ == '__main__':
    main()
