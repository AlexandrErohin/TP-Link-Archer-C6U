from unittest import TestCase
from unittest.mock import patch

from tplinkrouterc6u.client.c80 import TplinkMR515Router


class TestMR515LTEStatus(TestCase):
    def setUp(self):
        self.router = TplinkMR515Router('http://192.0.2.1', 'password')

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

    def test_lte_boolean_parser_handles_missing_and_invalid_values(self):
        self.assertIsNone(self.router._lte_bool(None))
        self.assertIsNone(self.router._lte_bool('2'))
        self.assertIs(self.router._lte_bool('0'), False)
        self.assertIs(self.router._lte_bool('1'), True)


if __name__ == '__main__':
    from unittest import main
    main()
